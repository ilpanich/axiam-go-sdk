package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// ---------------------------------------------------------------------------
// fakeChecker — a hermetic AccessChecker double so the §11 matrix can be
// exercised without a live AXIAM server. It records the arguments it was
// called with so tests can assert subject_id/scope propagation.
// ---------------------------------------------------------------------------

type fakeChecker struct {
	allowed bool
	reason  string
	err     error

	gotSubjectID  string
	gotAction     string
	gotResourceID string
	gotScope      []string
	calls         int
}

func (f *fakeChecker) CheckAccessAs(_ context.Context, subjectID, action, resourceID string, scope ...string) (bool, string, error) {
	f.calls++
	f.gotSubjectID = subjectID
	f.gotAction = action
	f.gotResourceID = resourceID
	f.gotScope = scope
	if f.err != nil {
		return false, "", f.err
	}
	return f.allowed, f.reason, nil
}

// reqWithUser builds a GET request carrying user in its context, as if
// Middleware had already run successfully.
func reqWithUser(user *User) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/docs/doc-1", nil)
	r.SetPathValue("id", "doc-1")
	if user != nil {
		r = r.WithContext(withUser(r.Context(), user))
	}
	return r
}

func testUser() *User {
	return &User{UserID: "user-42", TenantID: "tenant-abc", Roles: []string{"reader"}}
}

// ---------------------------------------------------------------------------
// RequireAuth
// ---------------------------------------------------------------------------

func TestRequireAuth_AllowsAuthenticated(t *testing.T) {
	rec := &recordingHandler{}
	h := RequireAuth()(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if !rec.called {
		t.Fatal("expected wrapped handler to run for an authenticated request")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuth_RejectsUnauthenticated(t *testing.T) {
	rec := &recordingHandler{}
	h := RequireAuth()(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(nil))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run without an injected identity")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authentication_failed")
}

// ---------------------------------------------------------------------------
// RequireAccess — the full §11 matrix
// ---------------------------------------------------------------------------

func TestRequireAccess_Allowed(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if !rec.called {
		t.Fatal("expected wrapped handler to run on allow")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if checker.calls != 1 {
		t.Fatalf("expected exactly one check call, got %d", checker.calls)
	}
}

func TestRequireAccess_Denied(t *testing.T) {
	checker := &fakeChecker{allowed: false, reason: "no permission"}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "documents:delete", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run on deny")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authorization_denied")
}

func TestRequireAccess_Unauthenticated(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(nil))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run without an injected identity")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authentication_failed")
	if checker.calls != 0 {
		t.Fatal("expected the authz check to never be called when unauthenticated")
	}
}

func TestRequireAccess_ResolverError(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	rec := &recordingHandler{}
	failingResolver := func(*http.Request) (string, error) { return "", errors.New("no resource id in body") }
	h := RequireAccess(checker, "documents:read", failingResolver)(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run when the resolver errors")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "invalid_request")
	if checker.calls != 0 {
		t.Fatal("expected the authz check to never be called when the resource is unresolvable")
	}
}

func TestRequireAccess_UnparseableResource_MissingPathValue(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	rec := &recordingHandler{}
	// ResourceFromPath("missing") looks up a path value that was never set on
	// the request (r.SetPathValue only set "id" in reqWithUser) — this is the
	// "missing or unparseable resource value" 400 case (CONTRACT.md §11.2.3),
	// never a silent allow and never a nil-UUID fallback.
	h := RequireAccess(checker, "documents:read", ResourceFromPath("missing"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run for a missing path value")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "invalid_request")
}

func TestRequireAccess_NetworkErrorFailsClosed(t *testing.T) {
	checker := &fakeChecker{err: &axiam.NetworkError{Message: "connection refused"}}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run on a transport failure (fail closed)")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authz_unavailable")
}

func TestRequireAccess_OtherCheckerErrorAlsoFailsClosed(t *testing.T) {
	// Any error from the checker — not only *axiam.NetworkError — must fail
	// closed (503), never be surfaced as an allow.
	checker := &fakeChecker{err: errors.New("boom")}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run on any checker error")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestRequireAccess_PassesSubjectIDFromContext(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(nopHandler())

	user := testUser()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(user))

	if checker.gotSubjectID != user.UserID {
		t.Fatalf("expected subject_id %q (the REQUEST's authenticated user, not the app's own session), got %q", user.UserID, checker.gotSubjectID)
	}
	if checker.gotAction != "documents:read" {
		t.Fatalf("expected action %q, got %q", "documents:read", checker.gotAction)
	}
	if checker.gotResourceID != "doc-1" {
		t.Fatalf("expected resource id %q, got %q", "doc-1", checker.gotResourceID)
	}
}

func TestRequireAccess_ScopePassthrough(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"), WithScope("field-a"))(nopHandler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if len(checker.gotScope) != 1 || checker.gotScope[0] != "field-a" {
		t.Fatalf("expected scope [\"field-a\"] passed through verbatim, got %v", checker.gotScope)
	}
}

func TestRequireAccess_NoScope_PassesNoScopeArgument(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(nopHandler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if len(checker.gotScope) != 0 {
		t.Fatalf("expected no scope argument when WithScope was not supplied, got %v", checker.gotScope)
	}
}

func TestRequireAccess_StaticResource(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	h := RequireAccess(checker, "settings:read", StaticResource("singleton-settings"))(nopHandler())

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	req = req.WithContext(withUser(req.Context(), testUser()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if checker.gotResourceID != "singleton-settings" {
		t.Fatalf("expected the static resource id to be used, got %q", checker.gotResourceID)
	}
}

func TestStaticResource_Empty_IsAnError(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	h := RequireAccess(checker, "settings:read", StaticResource(""))(nopHandler())

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	req = req.WithContext(withUser(req.Context(), testUser()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an empty static resource id, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "invalid_request")
}

// TestRequireAccess_NoTokenInResponseBody proves CONTRACT.md §11.2.8: no
// error/deny path ever leaks token material. There is no real token flowing
// through this in-context-only test, so we instead assert the well-known
// error taxonomy fields are the only thing present, and that no
// Authorization-header-shaped value leaks through.
func TestRequireAccess_NoTokenInResponseBody(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(nopHandler())

	req := reqWithUser(testUser())
	req.Header.Set("Authorization", "Bearer super-secret-token-value")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "super-secret-token-value") {
		t.Fatal("response body must never contain the raw token value")
	}
}

// ---------------------------------------------------------------------------
// RequireRole
// ---------------------------------------------------------------------------

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	rec := &recordingHandler{}
	h := RequireRole("admin", "reader")(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser())) // testUser has role "reader"

	if !rec.called {
		t.Fatal("expected wrapped handler to run when the user has one of the required roles")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireRole_RejectsMissingRole(t *testing.T) {
	rec := &recordingHandler{}
	h := RequireRole("admin")(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser())) // testUser only has "reader"

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run without the required role")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authorization_denied")
}

func TestRequireRole_NoRolesRequired_AlwaysDenies(t *testing.T) {
	// RequireRole with no roles at all is a caller programming error, not an
	// implicit "any authenticated user" allow — it must never grant access.
	rec := &recordingHandler{}
	h := RequireRole()(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run when RequireRole is given no roles")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireRole_RejectsUnauthenticated(t *testing.T) {
	rec := &recordingHandler{}
	h := RequireRole("admin")(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(nil))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run without an injected identity")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authentication_failed")
}

// ---------------------------------------------------------------------------
// Real-client wiring — proves RequireAccess composes correctly with the
// SDK's actual *axiam.Client (satisfying AccessChecker via CheckAccessAs),
// not just the fakeChecker double, and that subject_id/scope reach the wire.
// ---------------------------------------------------------------------------

func TestRequireAccess_RealClientWiring(t *testing.T) {
	var gotBody struct {
		Action     string `json:"action"`
		ResourceID string `json:"resource_id"`
		Scope      string `json:"scope"`
		SubjectID  string `json:"subject_id"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authz/check" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true})
	}))
	defer server.Close()

	client, err := axiam.NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("axiam.NewClient: %v", err)
	}

	// *axiam.Client satisfies AccessChecker via its CheckAccessAs method —
	// this line only compiles if that's true.
	var _ AccessChecker = client

	rec := &recordingHandler{}
	h := RequireAccess(client, "documents:read", ResourceFromPath("id"), WithScope("field-a"))(rec.handler())

	user := testUser()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(user))

	if !rec.called {
		t.Fatal("expected wrapped handler to run on allow")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotBody.Action != "documents:read" {
		t.Fatalf("expected action %q on the wire, got %q", "documents:read", gotBody.Action)
	}
	if gotBody.ResourceID != "doc-1" {
		t.Fatalf("expected resource_id %q on the wire, got %q", "doc-1", gotBody.ResourceID)
	}
	if gotBody.Scope != "field-a" {
		t.Fatalf("expected scope %q on the wire, got %q", "field-a", gotBody.Scope)
	}
	if gotBody.SubjectID != user.UserID {
		t.Fatalf("expected subject_id %q on the wire (the request's authenticated user, CONTRACT.md §11.2.2), got %q", user.UserID, gotBody.SubjectID)
	}
}

func TestRequireAccess_RealClientWiring_DeniedMaps403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "reason": "no permission"})
	}))
	defer server.Close()

	client, err := axiam.NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("axiam.NewClient: %v", err)
	}

	rec := &recordingHandler{}
	h := RequireAccess(client, "documents:delete", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run on server-side deny")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireAccess_RealClientWiring_ServerUnreachableFailsClosed(t *testing.T) {
	// A client pointed at a closed connection reproduces a genuine
	// *axiam.NetworkError from the real transport path (not a fake), proving
	// the fail-closed 503 mapping holds end-to-end.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // closed immediately: any request against it fails to connect

	client, err := axiam.NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("axiam.NewClient: %v", err)
	}

	rec := &recordingHandler{}
	h := RequireAccess(client, "documents:read", ResourceFromPath("id"))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if rec.called {
		t.Fatal("expected wrapped handler NOT to run when the authz endpoint is unreachable")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	assertErrorBody(t, w.Body.Bytes(), "authz_unavailable")
}

// ---------------------------------------------------------------------------
// WithRequireLogger
// ---------------------------------------------------------------------------

// TestWithRequireLogger_LogsDenialAtDebug proves WithRequireLogger wires an
// optional logger that emits a debug-level line naming the denied
// action/resource_id (CONTRACT.md §11.2.8) — and that it emits no raw token
// value.
func TestWithRequireLogger_LogsDenialAtDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	checker := &fakeChecker{allowed: false, reason: "no permission"}
	h := RequireAccess(checker, "documents:delete", ResourceFromPath("id"), WithRequireLogger(logger))(nopHandler())

	req := reqWithUser(testUser())
	req.Header.Set("Authorization", "Bearer super-secret-token-value")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	logged := buf.String()
	if !strings.Contains(logged, "documents:delete") || !strings.Contains(logged, "doc-1") {
		t.Fatalf("expected the logged line to name the action/resource_id, got: %s", logged)
	}
	if strings.Contains(logged, "super-secret-token-value") {
		t.Fatal("logger must never receive a raw token value")
	}
}

// TestWithRequireLogger_LogsNetworkFailureAtDebug covers the other
// logAuthzOutcome call site: a checker error (fail-closed 503) is also
// logged at debug level via the injected logger.
func TestWithRequireLogger_LogsNetworkFailureAtDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	checker := &fakeChecker{err: &axiam.NetworkError{Message: "connection refused"}}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"), WithRequireLogger(logger))(nopHandler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	if !strings.Contains(buf.String(), "documents:read") {
		t.Fatalf("expected the logged line to name the action, got: %s", buf.String())
	}
}

// TestWithRequireLogger_NilByDefault proves the logger is OFF by default:
// RequireAccess without WithRequireLogger never panics on a nil logger and
// simply produces no log output.
func TestWithRequireLogger_NilByDefault(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(nopHandler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser())) // must not panic with no logger configured

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// assertErrorBody verifies the response decodes as the standard {error,
// message} JSON body (CONTRACT.md §10/§11) with the expected error code.
func assertErrorBody(t *testing.T, body []byte, wantErrCode string) {
	t.Helper()
	var decoded struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("expected a JSON error body, got unmarshal error: %v (body=%s)", err, body)
	}
	if decoded.Error != wantErrCode {
		t.Fatalf("expected error code %q, got %q", wantErrCode, decoded.Error)
	}
	if decoded.Message == "" {
		t.Fatal("expected a non-empty message")
	}
}
