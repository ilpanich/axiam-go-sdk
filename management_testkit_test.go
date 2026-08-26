package axiam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Shared scaffolding for the CONTRACT §27 management tests.
//
// The generated conformance suite and the hand-written semantics suites both
// build a client the same way: a real Login against a mocked endpoint, so the
// org and tenant UUIDs the management routes interpolate come from the access
// token's claims exactly as they would in production, rather than being poked
// into unexported fields by the test.

var (
	// orgID is the organization UUID the test client's access token carries.
	orgID = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	// tenantID is the tenant UUID the test client's access token carries.
	tenantID = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	// exampleID is what the generated cases pass for every {..._id} parameter.
	exampleID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
)

// managementTestServer records the routes a test mounts and serves them,
// failing the test on anything it did not expect.
type managementTestServer struct {
	t       *testing.T
	server  *httptest.Server
	mu      chan struct{}
	routes  map[string]*mountedRoute
	unknown []string
}

// mountedRoute is one mounted response, and what actually reached it.
type mountedRoute struct {
	status   int
	body     string
	handler  func(w http.ResponseWriter, r *http.Request)
	requests []*recordedRequest
}

// recordedRequest is what a mounted route saw.
type recordedRequest struct {
	method string
	path   string
	query  url.Values
	body   []byte
	header http.Header
}

func routeKey(method, path string) string { return method + " " + path }

// managementServer starts a server with a mocked login and returns it beside a
// client that has already logged in against it.
func managementServer(t *testing.T) (*managementTestServer, *Client) {
	t.Helper()
	srv := &managementTestServer{t: t, routes: map[string]*mountedRoute{}, mu: make(chan struct{}, 1)}
	srv.mu <- struct{}{}

	srv.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: managementAccessToken(t), Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900,
			})
			return
		}
		srv.serve(w, r)
	}))
	t.Cleanup(srv.server.Close)

	client, err := NewClient(srv.server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Login(context.Background(), "admin@example.test", "hunter2hunter2"); err != nil {
		t.Fatalf("login: %v", err)
	}
	return srv, client
}

// anonymousManagementServer is the same server with a client that never logged
// in, for the §27.4 rule 1 refusals.
func anonymousManagementServer(t *testing.T) (*managementTestServer, *Client) {
	t.Helper()
	srv, _ := managementServer(t)
	anonymous, err := NewClient(srv.server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = anonymous.Close() })
	return srv, anonymous
}

func (s *managementTestServer) lock()   { <-s.mu }
func (s *managementTestServer) unlock() { s.mu <- struct{}{} }

// mount answers method+path with status and body. The match is exact, so an
// operation that sends its request somewhere other than the registry's path
// fails here rather than falling through to another mock.
func (s *managementTestServer) mount(method, path string, status int, body string) *mountedRoute {
	s.lock()
	defer s.unlock()
	route := &mountedRoute{status: status, body: body}
	s.routes[routeKey(method, path)] = route
	return route
}

// mountFunc answers method+path with a handler, for the cases that need to vary
// their reply across calls.
func (s *managementTestServer) mountFunc(method, path string, h func(w http.ResponseWriter, r *http.Request)) *mountedRoute {
	s.lock()
	defer s.unlock()
	route := &mountedRoute{handler: h}
	s.routes[routeKey(method, path)] = route
	return route
}

func (s *managementTestServer) serve(w http.ResponseWriter, r *http.Request) {
	body := readAllBody(r)
	s.lock()
	route, ok := s.routes[routeKey(r.Method, r.URL.Path)]
	if !ok {
		s.unknown = append(s.unknown, routeKey(r.Method, r.URL.Path))
		s.unlock()
		http.Error(w, "no route mounted for "+routeKey(r.Method, r.URL.Path), http.StatusNotImplemented)
		return
	}
	route.requests = append(route.requests, &recordedRequest{
		method: r.Method, path: r.URL.Path, query: r.URL.Query(),
		body: body, header: r.Header.Clone(),
	})
	handler := route.handler
	status, payload := route.status, route.body
	s.unlock()

	if handler != nil {
		handler(w, r)
		return
	}
	if payload == "" {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(payload))
}

// calls returns how many requests reached this route.
func (r *mountedRoute) calls() int { return len(r.requests) }

// last returns the most recent request this route saw.
func (r *mountedRoute) last(t *testing.T) *recordedRequest {
	t.Helper()
	if len(r.requests) == 0 {
		t.Fatal("route was never called")
	}
	return r.requests[len(r.requests)-1]
}

// jsonBody decodes the recorded request body as a JSON object.
func (r *recordedRequest) jsonBody(t *testing.T) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatalf("request body was not a JSON object: %v (%s)", err, string(r.body))
	}
	return out
}

// keys returns the body's key set, sorted — asserting the whole set is what
// §27.9 requires of a sparse update, because asserting one key is present
// passes even when every other field went along as null.
func (r *recordedRequest) keys(t *testing.T) []string {
	t.Helper()
	return sortedKeys(r.jsonBody(t))
}

func readAllBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf
		}
	}
}

// managementAccessToken builds the unsigned JWT the mocked login sets.
//
// Signature verification is not this layer's job (internal/jwks owns it); what
// matters is that org_id and tenant_id reach the client through the same
// unverified-claims decode a real login uses.
func managementAccessToken(t *testing.T) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"sub":       "11111111-1111-1111-1111-111111111111",
		"tenant_id": tenantID.String(),
		"org_id":    orgID.String(),
		"jti":       "33333333-3333-3333-3333-333333333333",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig"))
}

// expectedSurface is every namespace.operation the registry declares, sorted.
//
// Read from the registry rather than restated here, so a registry that grows an
// operation fails the generated suite until the surface is regenerated.
func expectedSurface(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("management-registry.json")
	if err != nil {
		t.Fatalf("read management-registry.json: %v", err)
	}
	var doc struct {
		Namespaces map[string]struct {
			Operations map[string]json.RawMessage `json:"operations"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse management-registry.json: %v", err)
	}
	var out []string
	for ns, def := range doc.Namespaces {
		for op := range def.Operations {
			out = append(out, ns+"."+op)
		}
	}
	sort.Strings(out)
	return out
}

// totalCalls is how many requests every mounted route has seen.
func (s *managementTestServer) totalCalls() int {
	s.lock()
	defer s.unlock()
	n := 0
	for _, route := range s.routes {
		n += len(route.requests)
	}
	return n + len(s.unknown)
}
