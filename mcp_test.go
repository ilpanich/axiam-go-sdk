package axiam

// CONTRACT.md §28.9 required tests 1 and 2 — the two that need no framework:
// the document's shape and its validation negatives, and the challenge's
// quoting and its refusals. Tests 3 (401 with the challenge), 4 (403
// insufficient_scope), 5 (aud mismatch) and the off-by-default regression
// live in middleware/mcp_test.go, which needs an *http.ServeMux.
//
// §28.9 asks for the same five assertions, on the same fixtures, in every
// SDK repository, so a divergence between this port and the TypeScript
// reference implementation (T9b) shows up as a different expected value
// rather than as a different test.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// §28.9's fixture — ONE configuration, shared by every §28 test in this
// repository (this file and middleware/mcp_test.go), quoted verbatim from
// the contract.
const (
	fixtureResource     = "https://mcp.example.com/mcp"
	fixtureAuthServer   = "https://axiam.example.com"
	fixtureDocs         = "https://mcp.example.com/docs"
	fixtureMetadataPath = "/.well-known/oauth-protected-resource/mcp"
	fixtureMetadataURL  = "https://mcp.example.com" + fixtureMetadataPath
	fixtureExpectedAud  = "https://mcp.example.com/mcp" // equal to fixtureResource
)

func fixtureOptions() ProtectedResourceMetadataOptions {
	return ProtectedResourceMetadataOptions{
		Resource:               fixtureResource,
		AuthorizationServers:   []string{fixtureAuthServer},
		ScopesSupported:        []string{"mcp:read", "mcp:tools"},
		BearerMethodsSupported: []string{"header"}, // the default
		ResourceDocumentation:  fixtureDocs,
	}
}

// §28.4's four normative test vectors, as exact strings.
const (
	vectorNoCredential      = `Bearer resource_metadata="` + fixtureMetadataURL + `"`
	vectorInvalidToken      = `Bearer error="invalid_token", resource_metadata="` + fixtureMetadataURL + `"`
	vectorInsufficientScope = `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="` + fixtureMetadataURL + `"`
	vectorAllFour           = `Bearer error="invalid_request", error_description="The access token is malformed", scope="mcp:read mcp:tools", resource_metadata="` + fixtureMetadataURL + `"`
)

func wantValidationError(t *testing.T, err error) *ValidationError {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T (%v)", err, err)
	}
	return ve
}

// ---------------------------------------------------------------------------
// §28.9 test 1 — document shape, and the validation negatives
// ---------------------------------------------------------------------------

func TestProtectedResourceMetadata_FixtureProducesExactDocument(t *testing.T) {
	metadata, err := ProtectedResourceMetadata(fixtureOptions())
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}

	// §28.2: member order in JSON is not semantically significant, so this
	// compares parsed values. The struct's field order still fixes the
	// emitted bytes (checked separately below) so there is one obvious
	// answer.
	want := map[string]any{
		"resource":                 fixtureResource,
		"authorization_servers":    []any{fixtureAuthServer},
		"scopes_supported":         []any{"mcp:read", "mcp:tools"},
		"bearer_methods_supported": []any{"header"},
		"resource_documentation":   fixtureDocs,
	}
	body, err := json.Marshal(metadata.Document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("document mismatch:\n got  %#v\n want %#v", got, want)
	}

	const wantOrder = `{"resource":"https://mcp.example.com/mcp","authorization_servers":["https://axiam.example.com"],"scopes_supported":["mcp:read","mcp:tools"],"bearer_methods_supported":["header"],"resource_documentation":"https://mcp.example.com/docs"}`
	if string(body) != wantOrder {
		t.Fatalf("document member order mismatch:\n got  %s\n want %s", body, wantOrder)
	}

	if metadata.MetadataPath != fixtureMetadataPath {
		t.Fatalf("MetadataPath = %q, want %q", metadata.MetadataPath, fixtureMetadataPath)
	}
	if metadata.MetadataURL != fixtureMetadataURL {
		t.Fatalf("MetadataURL = %q, want %q", metadata.MetadataURL, fixtureMetadataURL)
	}
}

func TestProtectedResourceMetadata_DerivesEveryMetadataPath(t *testing.T) {
	// A trailing slash is carried through rather than trimmed: it is part
	// of the resource identifier the client will compare, and two
	// resources that differ only by it are two resources.
	cases := []struct{ resource, path string }{
		{"https://mcp.example.com", "/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com/", "/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"},
		{"https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"},
		{"https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"},
	}
	for _, c := range cases {
		opts := fixtureOptions()
		opts.Resource = c.resource
		metadata, err := ProtectedResourceMetadata(opts)
		if err != nil {
			t.Fatalf("resource=%q: %v", c.resource, err)
		}
		if metadata.MetadataPath != c.path {
			t.Errorf("resource=%q: MetadataPath = %q, want %q", c.resource, metadata.MetadataPath, c.path)
		}
		if want := "https://mcp.example.com" + c.path; metadata.MetadataURL != want {
			t.Errorf("resource=%q: MetadataURL = %q, want %q", c.resource, metadata.MetadataURL, want)
		}
		// The document keeps the resource exactly as written.
		if metadata.Document.Resource != c.resource {
			t.Errorf("resource=%q: Document.Resource = %q", c.resource, metadata.Document.Resource)
		}
	}
}

func TestProtectedResourceMetadata_RefusesRelativeFragmentOrQueryResource(t *testing.T) {
	for _, resource := range []string{
		"/mcp",
		"mcp.example.com/mcp",
		"https://mcp.example.com/mcp#tools",
		// §28.3 derives the document's own URL from this value and a query
		// makes that derivation ambiguous — so §28 forbids what RFC 8707
		// permits.
		"https://mcp.example.com/mcp?tenant_id=acme",
		"",
	} {
		opts := fixtureOptions()
		opts.Resource = resource
		if _, err := ProtectedResourceMetadata(opts); err == nil {
			t.Errorf("resource=%q: expected a refusal", resource)
		} else {
			wantValidationError(t, err)
		}
	}
}

func TestProtectedResourceMetadata_HTTPOnlyOnLoopback(t *testing.T) {
	opts := fixtureOptions()
	opts.Resource = "http://mcp.example.com/mcp"
	if _, err := ProtectedResourceMetadata(opts); err == nil {
		t.Fatal("expected http on a routable host to be refused")
	} else {
		wantValidationError(t, err)
	}

	loopback := fixtureOptions()
	loopback.Resource = "http://127.0.0.1:8080/mcp"
	loopback.AuthorizationServers = []string{"http://localhost:9000"}
	metadata, err := ProtectedResourceMetadata(loopback)
	if err != nil {
		t.Fatalf("expected loopback http to be accepted: %v", err)
	}
	if metadata.Document.Resource != "http://127.0.0.1:8080/mcp" {
		t.Fatalf("Document.Resource = %q", metadata.Document.Resource)
	}
	if want := "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp"; metadata.MetadataURL != want {
		t.Fatalf("MetadataURL = %q, want %q", metadata.MetadataURL, want)
	}

	// The carve-out is the host, not a substring of it: an authority whose
	// userinfo merely READS localhost resolves to a routable host.
	spoofed := fixtureOptions()
	spoofed.Resource = "http://localhost@evil.example.com/mcp"
	if _, err := ProtectedResourceMetadata(spoofed); err == nil {
		t.Fatal("expected userinfo-spoofed localhost to be refused")
	}

	// §28.2 rule 2 names three hosts; [::1] is the third, and the brackets
	// are part of the host rather than punctuation around it.
	v6 := fixtureOptions()
	v6.Resource = "http://[::1]:8080/mcp"
	v6.AuthorizationServers = []string{"http://[::1]:9000"}
	v6meta, err := ProtectedResourceMetadata(v6)
	if err != nil {
		t.Fatalf("expected [::1] to be accepted: %v", err)
	}
	if want := "http://[::1]:8080/.well-known/oauth-protected-resource/mcp"; v6meta.MetadataURL != want {
		t.Fatalf("MetadataURL = %q, want %q", v6meta.MetadataURL, want)
	}

	v6routable := fixtureOptions()
	v6routable.Resource = "http://[2001:db8::1]:8080/mcp"
	if _, err := ProtectedResourceMetadata(v6routable); err == nil {
		t.Fatal("expected a routable IPv6 host to be refused")
	}
}

func TestProtectedResourceMetadata_RefusesBadAuthorizationServers(t *testing.T) {
	cases := [][]string{
		{}, // empty: answers none of the question
		{"https://axiam.example.com?tenant_id=a"},                  // query
		{"https://axiam.example.com#frag"},                         // fragment
		{"https://axiam.example.com", "https://axiam.example.com"}, // duplicate
	}
	for _, servers := range cases {
		opts := fixtureOptions()
		opts.AuthorizationServers = servers
		if _, err := ProtectedResourceMetadata(opts); err == nil {
			t.Errorf("authorization_servers=%v: expected a refusal", servers)
		} else {
			wantValidationError(t, err)
		}
	}
}

func TestProtectedResourceMetadata_ScopesSupported(t *testing.T) {
	for _, scopes := range [][]string{
		{"mcp:read", "mcp:read"}, // duplicate
		{"mcp read"},             // space
		{"mcp:\"read\""},         // quote
		{""},                     // empty token
	} {
		opts := fixtureOptions()
		opts.ScopesSupported = scopes
		if _, err := ProtectedResourceMetadata(opts); err == nil {
			t.Errorf("scopes_supported=%v: expected a refusal", scopes)
		} else {
			wantValidationError(t, err)
		}
	}

	// The order is the caller's, never sorted.
	opts := fixtureOptions()
	opts.ScopesSupported = []string{"mcp:tools", "mcp:read"}
	metadata, err := ProtectedResourceMetadata(opts)
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}
	if !reflect.DeepEqual(metadata.Document.ScopesSupported, []string{"mcp:tools", "mcp:read"}) {
		t.Fatalf("ScopesSupported = %v, want caller order preserved", metadata.Document.ScopesSupported)
	}
}

func TestProtectedResourceMetadata_BearerMethodsSupported(t *testing.T) {
	for _, methods := range [][]string{
		{"query"},
		{"header", "body"},
		{},
		{"header", "header"},
	} {
		opts := fixtureOptions()
		opts.BearerMethodsSupported = methods
		if _, err := ProtectedResourceMetadata(opts); err == nil {
			t.Errorf("bearer_methods_supported=%v: expected a refusal", methods)
		} else {
			wantValidationError(t, err)
		}
	}

	// nil means the default, and the default is the only accepted value.
	opts := fixtureOptions()
	opts.BearerMethodsSupported = nil
	metadata, err := ProtectedResourceMetadata(opts)
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}
	if !reflect.DeepEqual(metadata.Document.BearerMethodsSupported, []string{"header"}) {
		t.Fatalf("BearerMethodsSupported = %v", metadata.Document.BearerMethodsSupported)
	}
}

func TestProtectedResourceMetadata_OmitsEmptyScopesAndAbsentDocumentation(t *testing.T) {
	metadata, err := ProtectedResourceMetadata(ProtectedResourceMetadataOptions{
		Resource:             fixtureResource,
		AuthorizationServers: []string{fixtureAuthServer},
		ScopesSupported:      []string{},
	})
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}

	body, err := json.Marshal(metadata.Document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["scopes_supported"]; ok {
		t.Error("scopes_supported must be omitted, not emitted empty")
	}
	if _, ok := raw["resource_documentation"]; ok {
		t.Error("resource_documentation must be omitted, not emitted null")
	}
	// An explicit null is not an omission — assert the string never
	// contains one.
	if strings.Contains(string(body), "null") {
		t.Errorf("document must never contain a JSON null: %s", body)
	}
}

func TestProtectedResourceMetadata_ResourceDocumentationAllowsQueryAndFragment(t *testing.T) {
	opts := fixtureOptions()
	opts.ResourceDocumentation = "https://mcp.example.com/docs?v=2#tools"
	metadata, err := ProtectedResourceMetadata(opts)
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}
	if metadata.Document.ResourceDocumentation != "https://mcp.example.com/docs?v=2#tools" {
		t.Fatalf("ResourceDocumentation = %q", metadata.Document.ResourceDocumentation)
	}

	httpDocs := fixtureOptions()
	httpDocs.ResourceDocumentation = "http://docs.example.com/mcp"
	if _, err := ProtectedResourceMetadata(httpDocs); err == nil {
		t.Fatal("expected http resource_documentation on a non-loopback host to be refused")
	}
}

// ---------------------------------------------------------------------------
// §28.9 test 2 — challenge quoting
// ---------------------------------------------------------------------------

func TestBearerChallenge_FourVectors(t *testing.T) {
	got, err := BearerChallenge(BearerChallengeOptions{ResourceMetadataURL: fixtureMetadataURL})
	if err != nil || got != vectorNoCredential {
		t.Fatalf("vector 1: got (%q, %v), want %q", got, err, vectorNoCredential)
	}

	got, err = BearerChallenge(BearerChallengeOptions{ResourceMetadataURL: fixtureMetadataURL, Error: BearerChallengeErrorInvalidToken})
	if err != nil || got != vectorInvalidToken {
		t.Fatalf("vector 2: got (%q, %v), want %q", got, err, vectorInvalidToken)
	}

	got, err = BearerChallenge(BearerChallengeOptions{
		ResourceMetadataURL: fixtureMetadataURL,
		Error:               BearerChallengeErrorInsufficientScope,
		Scope:               "mcp:tools",
	})
	if err != nil || got != vectorInsufficientScope {
		t.Fatalf("vector 3: got (%q, %v), want %q", got, err, vectorInsufficientScope)
	}

	// Parameter order is fixed — error, error_description, scope,
	// resource_metadata — separated by exactly ", ".
	got, err = BearerChallenge(BearerChallengeOptions{
		ResourceMetadataURL: fixtureMetadataURL,
		Error:               BearerChallengeErrorInvalidRequest,
		ErrorDescription:    "The access token is malformed",
		Scope:               "mcp:read mcp:tools",
	})
	if err != nil || got != vectorAllFour {
		t.Fatalf("vector 4: got (%q, %v), want %q", got, err, vectorAllFour)
	}
}

func TestBearerChallenge_RefusesUndefinedErrorCode(t *testing.T) {
	// Not even a well-formed-looking OAuth error code: invalid_grant is a
	// token-endpoint error and has no meaning in a challenge.
	_, err := BearerChallenge(BearerChallengeOptions{ResourceMetadataURL: fixtureMetadataURL, Error: "invalid_grant"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	wantValidationError(t, err)
}

func TestBearerChallenge_RefusesRatherThanEscapesErrorDescription(t *testing.T) {
	for _, description := range []string{
		`he said "no"`,
		`a back\slash`,
		"two\nlines",
		"a control\x01",
		"non-ASCII: café",
	} {
		_, err := BearerChallenge(BearerChallengeOptions{
			ResourceMetadataURL: fixtureMetadataURL,
			Error:               BearerChallengeErrorInvalidRequest,
			ErrorDescription:    description,
		})
		if err == nil {
			t.Errorf("error_description=%q: expected a refusal", description)
			continue
		}
		ve := wantValidationError(t, err)
		// No escaping occurred: the refusal is an error, never a challenge
		// carrying a backslash-escaped quote.
		if strings.Contains(ve.Error(), `\"`) {
			t.Errorf("error_description=%q: refusal message must not contain an escaped quote: %s", description, ve.Error())
		}
	}
}

func TestBearerChallenge_RefusesBadScope(t *testing.T) {
	// "" is deliberately excluded here — a Go divergence from T9b's test
	// (see the PR description): BearerChallengeOptions has no
	// present-but-empty distinct from absent (Go's zero value for string
	// IS ""), and every other option in this SDK already treats "" as
	// "not given" (e.g. ResourceMetadataURL, RequireOption's scope). A
	// caller cannot express "explicitly empty scope" any more than they
	// can express "explicitly empty resource_metadata_url", so
	// Scope: "" omits the scope parameter rather than refusing.
	for _, scope := range []string{" mcp:read", "mcp:read ", "mcp:read  mcp:tools", " ", `mcp:"read"`} {
		_, err := BearerChallenge(BearerChallengeOptions{
			ResourceMetadataURL: fixtureMetadataURL,
			Error:               BearerChallengeErrorInsufficientScope,
			Scope:               scope,
		})
		if err == nil {
			t.Errorf("scope=%q: expected a refusal", scope)
			continue
		}
		wantValidationError(t, err)
	}
}

func TestBearerChallenge_RefusesUnencodedResourceMetadata(t *testing.T) {
	for _, url := range []string{
		"https://mcp.example.com/.well-known/oauth protected resource",
		`https://mcp.example.com/"quoted"`,
		`https://mcp.example.com/back\slash`,
		"/.well-known/oauth-protected-resource/mcp",
		"http://mcp.example.com/.well-known/oauth-protected-resource/mcp",
	} {
		_, err := BearerChallenge(BearerChallengeOptions{ResourceMetadataURL: url})
		if err == nil {
			t.Errorf("resource_metadata=%q: expected a refusal", url)
			continue
		}
		wantValidationError(t, err)
	}

	// It MAY carry a query and a fragment, unlike the resource identifier.
	got, err := BearerChallenge(BearerChallengeOptions{ResourceMetadataURL: fixtureMetadataURL + "?v=2#x"})
	if err != nil {
		t.Fatalf("BearerChallenge: %v", err)
	}
	if want := `Bearer resource_metadata="` + fixtureMetadataURL + `?v=2#x"`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
