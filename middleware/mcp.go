package middleware

// This file implements the guard side of CONTRACT.md §28 (MCP
// Resource-Server Helpers, RFC 9728): ServeProtectedResourceMetadata (§28.3)
// plus the WithResourceMetadataURL / WithRequireResourceMetadataURL guard
// options (§28.5) that nethttp.go and require.go wire into Middleware,
// RequireAccess and RequireAuth. axiam.ProtectedResourceMetadata and
// axiam.BearerChallenge — the two pure, network-free §28 operations — live
// in the root package, mirroring where axiam.UmaChallengeHeader lives for
// §20.3.
//
// §28 is opt-in and off by default (§28.5 rule 1): every function here
// returns nil/emits nothing when its ResourceMetadataURL option is unset,
// which is what keeps a guard without §28 byte-for-byte identical to one
// from before §28 existed.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// AccessDecisionChecker is the richer form of AccessChecker that also
// surfaces the §11 rule 9 ReasonCode a decision carried — satisfied by
// *axiam.Client's CheckAccessDecision. RequireAccess consults it, via a
// type assertion, only when a §28.5 rule 5 insufficient_scope challenge is
// even possible (ResourceMetadataURL and a route Scope both configured):
// that is the only place a reason_code is needed, and it is read this way
// rather than by widening AccessChecker itself so every existing
// AccessChecker fake keeps compiling and keeps behaving exactly as it did
// before §28. A checker that implements only AccessChecker still works
// under §28: RequireAccess then treats the reason_code as unrecognised and
// emits no challenge, which §28.5 rule 5 already defines as correct for an
// unrecognised code.
type AccessDecisionChecker interface {
	CheckAccessDecision(ctx context.Context, subjectID, action, resourceID string, scope ...string) (axiam.AccessResult, error)
}

// mcpChallenges holds the §28.4 challenge values a guard emits, all built
// once at guard-construction time (buildMCPChallenges) so that an invalid
// configuration is a startup failure rather than a surprise on the 401
// path. nil (the zero value of *mcpChallenges) means §28 is off.
type mcpChallenges struct {
	// noCredential is §28.4 vector 1: the request carried no authentication
	// information, so RFC 6750 §3 says not to name an error.
	noCredential string
	// invalidToken is §28.4 vector 2: a credential was presented and
	// rejected. The only thing a 401 this SDK emits ever says about why.
	invalidToken string
	// insufficientScope is §28.4 vector 3, present only where the guard was
	// configured with a route scope (RequireAccess's WithScope) — "" when
	// there is none to challenge for.
	insufficientScope string
	// metadataPath is the document's path, exempted from authentication by
	// Middleware (§28.3 rule 2).
	metadataPath string
}

// buildMCPChallenges validates resourceMetadataURL and precomputes the
// challenges a guard emits (§28.5). Returns nil when resourceMetadataURL is
// "" — §28 is off, which is how "off" stays byte-for-byte indistinguishable
// from "absent" (§28.5 rule 1). scope is RequireAccess's own route-level
// scope argument (§28.5 rule 5); pass "" for Middleware/RequireAuth, neither
// of which has one.
//
// PANICS when resourceMetadataURL is not a valid absolute URI per §28.2
// rules 1-2, or scope is outside §28.4's syntax — both detected by
// delegating to axiam.BearerChallenge's own validation. This is
// Middleware/RequireAccess/RequireAuth's equivalent of the TypeScript
// reference implementation's synchronous throw from the guard factory
// itself (see the "T9b divergence" note in the PR description): none of
// those three Go constructors has an error return to refuse a bad
// configuration through — Middleware and RequireAccess predate §28 by
// several contract versions, and widening either signature (or adding one
// to RequireAuth, which previously took none) to accommodate one opt-in
// feature would break every existing caller. Go's idiomatic equivalent of
// "fail synchronously, at setup, before a request is served, with no error
// channel available" is a panic — the same class as regexp.MustCompile,
// raised once, at construction, never on the request path.
func buildMCPChallenges(operation, resourceMetadataURL, scope string) *mcpChallenges {
	if resourceMetadataURL == "" {
		return nil
	}

	noCredential, err := axiam.BearerChallenge(axiam.BearerChallengeOptions{
		ResourceMetadataURL: resourceMetadataURL,
	})
	if err != nil {
		panic(fmt.Sprintf("axiam: middleware.%s: %s", operation, err.Error()))
	}
	invalidToken, err := axiam.BearerChallenge(axiam.BearerChallengeOptions{
		ResourceMetadataURL: resourceMetadataURL,
		Error:               axiam.BearerChallengeErrorInvalidToken,
	})
	if err != nil {
		panic(fmt.Sprintf("axiam: middleware.%s: %s", operation, err.Error()))
	}

	var insufficientScope string
	if scope != "" {
		insufficientScope, err = axiam.BearerChallenge(axiam.BearerChallengeOptions{
			ResourceMetadataURL: resourceMetadataURL,
			Error:               axiam.BearerChallengeErrorInsufficientScope,
			Scope:               scope,
		})
		if err != nil {
			panic(fmt.Sprintf("axiam: middleware.%s: %s", operation, err.Error()))
		}
	}

	return &mcpChallenges{
		noCredential:      noCredential,
		invalidToken:      invalidToken,
		insufficientScope: insufficientScope,
		metadataPath:      mcpMetadataPathOf(resourceMetadataURL),
	}
}

// mcpMetadataPathOf extracts the path component of an already-validated
// resourceMetadataURL, for the §28.3 rule 2 authentication exemption. "/"
// when the URL carries none, mirroring §28.3's own root-form derivation.
func mcpMetadataPathOf(resourceMetadataURL string) string {
	u, err := url.Parse(resourceMetadataURL)
	if err != nil {
		return ""
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// isMCPMetadataRequest reports whether r is the unauthenticated GET/HEAD of
// the metadata document (§28.3 rule 2). nil challenges (§28 off) or an
// empty metadataPath (buildMCPChallenges failed to derive one) never match.
func isMCPMetadataRequest(r *http.Request, mcp *mcpChallenges) bool {
	if mcp == nil || mcp.metadataPath == "" {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return r.URL.Path == mcp.metadataPath
}

// setMCPChallenge401 sets the response's WWW-Authenticate header for a 401
// Middleware is about to emit, picking §28.4's vector 1 or vector 2 by
// whether Middleware itself already determined a credential was presented
// (credentialPresented) — a no-op when mcp is nil (§28 off).
func setMCPChallenge401(w http.ResponseWriter, mcp *mcpChallenges, credentialPresented bool) {
	if mcp == nil {
		return
	}
	if credentialPresented {
		w.Header().Set("WWW-Authenticate", mcp.invalidToken)
		return
	}
	w.Header().Set("WWW-Authenticate", mcp.noCredential)
}

// setMCPChallenge401FromRequest is setMCPChallenge401 for a §11 guard
// (RequireAccess/RequireAuth) whose own 401 fires from a request that was
// never routed through Middleware's own extraction — so credential
// presence is determined fresh, from the raw request, exactly as Middleware
// itself would (extractToken). §28.4's vectors are chosen the same way
// either way: no credential at all is vector 1; a credential that was
// simply never verified (because Middleware was never mounted ahead of
// this guard) is, from the caller's perspective, indistinguishable from one
// that was verified and rejected — both are "a credential was presented",
// vector 2.
func setMCPChallenge401FromRequest(w http.ResponseWriter, r *http.Request, mcp *mcpChallenges) {
	if mcp == nil {
		return
	}
	_, _, err := extractToken(r)
	setMCPChallenge401(w, mcp, err == nil)
}

// setMCPChallenge403 sets the response's WWW-Authenticate header for the
// one class of 403 §28.5 rule 5 challenges: a route that named a scope,
// denied with reason_code no_grant. Every other 403 — denied_by_rule, an
// absent/unrecognised reason_code, no scope argument, mcp nil (§28 off) —
// is left untouched.
func setMCPChallenge403(w http.ResponseWriter, mcp *mcpChallenges, reasonCode string) {
	if mcp == nil || mcp.insufficientScope == "" {
		return
	}
	if reasonCode != axiam.ReasonCodeNoGrant {
		return
	}
	w.Header().Set("WWW-Authenticate", mcp.insufficientScope)
}

// ---------------------------------------------------------------------------
// §28.3 — ServeProtectedResourceMetadata
// ---------------------------------------------------------------------------

// MCPGuardConfig is the two §28.5 settings a guard carries, passed
// optionally to ServeProtectedResourceMetadata so it can cross-check them
// against the document it is about to serve (§28.5 rule 3). ExpectedAudience
// mirrors the value given to Middleware's WithExpectedAudience;
// ResourceMetadataURL mirrors WithResourceMetadataURL /
// WithRequireResourceMetadataURL — the SAME strings, not a second
// configuration surface (§28.5 rule 2's closing sentence).
//
// Where the guard is configured in a different process from the one
// serving the document, omit the cross-check entirely (call
// ServeProtectedResourceMetadata with no guard argument): nothing can be
// checked there, and the operator configures both processes from the one
// constant MCPResourceMetadata.MetadataURL / .Document.Resource already
// are.
type MCPGuardConfig struct {
	ExpectedAudience    string
	ResourceMetadataURL string
}

// ServeProtectedResourceMetadata registers the one GET route that serves
// the RFC 9728 document on mux, and returns the same metadata value so a
// guard's ResourceMetadataURL option can be fed from it rather than
// retyped (CONTRACT.md §28.1, §28.3).
//
// The path is derived, not chosen (axiam.ProtectedResourceMetadata already
// did that), and exactly one route is registered: the root form is not
// also registered for a resource that has a path, so a deployment fronting
// several resources can call this once per resource without the derived
// paths colliding.
//
// The response is 200 with Content-Type: application/json, the document as
// its body, Cache-Control: public, max-age=3600 and
// Access-Control-Allow-Origin: * — the last because an MCP client running
// in a browser cannot read the document without it, and it is safe
// precisely because the response is identical for every caller. It never
// sets Access-Control-Allow-Credentials, which would be asking a browser to
// attach the user's cookies to a request that has no use for them, and
// nothing is read from the request, so there is no Set-Cookie and no
// per-caller content. §3a does not apply: it is a GET, and §3a is scoped to
// state-changing methods and cookie-sourced credentials.
//
// Serving it needs no route-registration ordering relative to Middleware:
// where the §10 guard is mounted globally it exempts this exact path
// itself, from the ResourceMetadataURL it was configured with.
//
// guard, when given, is the guard session's MCPGuardConfig (§28.5 rule 3):
// this returns *axiam.ValidationError when guard.ResourceMetadataURL is not
// exactly metadata.MetadataURL, or guard.ExpectedAudience is not exactly
// metadata.Document.Resource — both simple string equality (RFC 3986
// §6.2.1), no normalisation, no case folding, no trailing-slash tolerance.
// Note the two comparisons are against DIFFERENT strings of metadata: the
// resource and the metadata URL are not one another, and an implementation
// that compared one against the other would reject the only correct
// configuration.
func ServeProtectedResourceMetadata(mux *http.ServeMux, metadata axiam.MCPResourceMetadata, guard ...MCPGuardConfig) (axiam.MCPResourceMetadata, error) {
	const op = "ServeProtectedResourceMetadata"

	if len(guard) > 0 {
		g := guard[0]
		if g.ResourceMetadataURL != metadata.MetadataURL {
			return axiam.MCPResourceMetadata{}, &axiam.ValidationError{
				Operation: op,
				Status:    400,
				Message: fmt.Sprintf(
					"%s: resourceMetadataURL: is %q but this document is published at %q — the challenge would point at a document that is not this resource server's (CONTRACT.md §28.5 rule 3)",
					op, g.ResourceMetadataURL, metadata.MetadataURL),
				Fields: []axiam.FieldError{{Field: "resourceMetadataURL", Message: "does not match this document's metadata URL"}},
			}
		}
		if g.ExpectedAudience != metadata.Document.Resource {
			return axiam.MCPResourceMetadata{}, &axiam.ValidationError{
				Operation: op,
				Status:    400,
				Message: fmt.Sprintf(
					"%s: expectedAudience: is %q but this document announces %q — the document would announce one identifier while the guard checked aud against another, so every token the flow produced would be refused (CONTRACT.md §28.5 rule 3)",
					op, g.ExpectedAudience, metadata.Document.Resource),
				Fields: []axiam.FieldError{{Field: "expectedAudience", Message: "does not match this document's resource"}},
			}
		}
	}

	// Serialized once: the response is identical for every caller (§28.3
	// rule 4), so there is nothing per-request to build.
	body, err := json.Marshal(metadata.Document)
	if err != nil {
		return axiam.MCPResourceMetadata{}, err
	}

	// A trailing-slash metadataPath is, to *http.ServeMux, an anonymous
	// "..." wildcard (a subtree match) unless pinned with {$}. §28.3
	// registers EXACTLY one route at EXACTLY the derived path — never a
	// subtree — so a path ending in "/" needs the pin; one that does not is
	// already an exact match.
	pattern := http.MethodGet + " " + metadata.MetadataPath
	if strings.HasSuffix(metadata.MetadataPath, "/") {
		pattern += "{$}"
	}
	mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
		// *http.ServeMux GET patterns also match HEAD automatically; the
		// response is identical either way since nothing here varies on
		// the request.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	return metadata, nil
}
