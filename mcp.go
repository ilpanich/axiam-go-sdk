package axiam

import (
	"fmt"
	"regexp"
	"strings"
)

// This file implements CONTRACT.md §28 (MCP Resource-Server Helpers, RFC
// 9728) — the RESOURCE SERVER's half of the Model Context Protocol
// authorization handshake: publishing the protected-resource metadata
// document that names the authorization server guarding this resource, and
// building the WWW-Authenticate challenge that starts a client's discovery.
// It is additive to §10 (middleware/route-guard) and consumes §11
// (declarative authorization helpers); it changes neither.
//
// NOTHING HERE IS A SOURCE OF TRUTH ABOUT A TOKEN. The document is a claim
// this resource server publishes about itself; the challenge is a hint
// given to a caller that already failed. Whether a request is authorized
// remains §10.1's and §11's decision, unchanged and unreachable from here.
//
// PURE LOCAL COMPUTATION, like UmaParseChallenge/UmaChallengeHeader: neither
// operation in this file performs network I/O, so §16's retry policy and
// §9's single-flight refresh guard do not apply, and neither touches a
// *Client's own session (§28.0).
//
// Go naming note (a documented T9b divergence — see the PR description):
// §28.7 pins this package's first operation's Go name to
// ProtectedResourceMetadata — the same name a struct literally holding "the
// document, its path, and its URL" would most naturally carry. Go has one
// identifier namespace for types and functions at package scope, so the two
// cannot share a name the way TypeScript's protectedResourceMetadata()
// function and ProtectedResourceMetadata interface do (TS keeps separate
// type/value namespaces). The function keeps the contract-mandated name;
// the struct it returns is MCPResourceMetadata.

// The three RFC 6750 §3.1 error codes a bearer challenge may name — the
// complete vocabulary (CONTRACT.md §28.4).
const (
	BearerChallengeErrorInvalidRequest    = "invalid_request"
	BearerChallengeErrorInvalidToken      = "invalid_token"
	BearerChallengeErrorInsufficientScope = "insufficient_scope"
)

// bearerMethodsSupportedDefault is §28.1's default and, in this contract
// version, its only accepted value (§28.2 rule 6).
var bearerMethodsSupportedDefault = []string{"header"}

// protectedResourceMetadataPrefix is RFC 9728 §3.1's well-known prefix — the
// segment inserted between a resource's authority and its path to reach the
// document that describes it (§28.3).
const protectedResourceMetadataPrefix = "/.well-known/oauth-protected-resource"

// loopbackHosts are the three hosts §28.2 rule 2 lets an http:// resource
// use — AXIAM's own RFC 8252 §7.3 loopback rule, reused verbatim. There is
// deliberately no flag, environment variable or debug build that widens
// this: a resource server reachable over plaintext on a routable host
// publishes an identifier an attacker can impersonate.
var loopbackHosts = map[string]bool{
	"127.0.0.1": true,
	"[::1]":     true,
	"localhost": true,
}

// ---------------------------------------------------------------------------
// Refusals (§28.2, §28.4) — always *ValidationError, never a new type
// (§28.6, §2).
// ---------------------------------------------------------------------------

// mcpRefuse builds §28's refusal: *ValidationError, the same sub-type §27's
// management surface already uses for a rejected request — §28.6 pins the
// error taxonomy at three types plus this classification and forbids a
// fourth. Status is 400 even though no server was asked and no request was
// made: it names the HTTP code an AXIAM server would answer with for the
// same rejected field.
func mcpRefuse(operation, field, message string) *ValidationError {
	return &ValidationError{
		Operation: operation,
		Status:    400,
		Message:   fmt.Sprintf("%s: %s: %s (CONTRACT.md §28)", operation, field, message),
		Fields:    []FieldError{{Field: field, Message: message}},
	}
}

// ---------------------------------------------------------------------------
// Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4.
// ---------------------------------------------------------------------------

// isNQChar reports whether r is an RFC 6749 Appendix A NQCHAR: %x21,
// %x23-%x5B, %x5D-%x7E. No space, no '"', no '\', no control character, no
// non-ASCII.
func isNQChar(r rune) bool {
	return r == 0x21 || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E)
}

// isNQSChar reports whether r is an NQSCHAR: NQCHAR plus the space (%x20).
func isNQSChar(r rune) bool {
	return r == 0x20 || isNQChar(r)
}

func isAllNQChar(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isNQChar(r) {
			return false
		}
	}
	return true
}

func isAllNQSChar(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isNQSChar(r) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Absolute-URI parsing (§28.2 rules 1, 2, 3, 7).
// ---------------------------------------------------------------------------

// absoluteURIRe matches scheme://authority[path][?query][#fragment] against
// the caller's string exactly as given.
//
// Deliberately not net/url.Parse: that parser NORMALISES — it can resolve
// "." and ".." segments and re-encode. §28.2 forbids adjusting a value to
// make it pass, and §28.3 derives the document's own path from this string,
// so what is validated must be what was written.
var absoluteURIRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)(\?[^#]*)?(#[\s\S]*)?$`)

// parsedURI is the pieces of an absolute URI, sliced out of the caller's
// string without normalisation.
type parsedURI struct {
	// scheme is the scheme, verbatim (compared case-insensitively, stored
	// as written).
	scheme string
	// authority is the authority, verbatim — userinfo@host:port included.
	authority string
	// path is the path component: empty, or starting with "/". A trailing
	// slash is preserved.
	path string
	// hasQuery is true when the string carried a "?", even an empty one.
	hasQuery bool
	// hasFragment is true when the string carried a "#", even an empty one.
	hasFragment bool
}

func parseAbsoluteURI(raw string) (parsedURI, bool) {
	m := absoluteURIRe.FindStringSubmatch(raw)
	if m == nil {
		return parsedURI{}, false
	}
	authority := m[2]
	if authority == "" {
		return parsedURI{}, false
	}
	return parsedURI{
		scheme:      m[1],
		authority:   authority,
		path:        m[3],
		hasQuery:    m[4] != "",
		hasFragment: m[5] != "",
	}, true
}

// hostOf returns the host inside an authority: userinfo@ stripped, port
// stripped, an IPv6 literal's brackets kept (so "[::1]" compares as §28.2
// rule 2 spells it).
//
// Stripping userinfo is what makes "http://localhost@evil.example.com/" a
// refusal rather than a loopback pass — the host there is
// evil.example.com.
func hostOf(authority string) string {
	hostport := authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		hostport = authority[at+1:]
	}
	if strings.HasPrefix(hostport, "[") {
		if close := strings.Index(hostport, "]"); close >= 0 {
			return hostport[:close+1]
		}
		return hostport
	}
	if colon := strings.Index(hostport, ":"); colon >= 0 {
		return hostport[:colon]
	}
	return hostport
}

// uriPolicy is how much of §28.2 rule 1 a particular member is held to —
// rule 7 and §28.4's resource_metadata relax the query/fragment parts of
// it.
type uriPolicy struct {
	// allowQuery is true for resource_documentation (§28.2 rule 7) and
	// resource_metadata (§28.4): a page for a human may be parameterised.
	allowQuery bool
	// allowFragment is true for the same two members, for the same reason.
	allowFragment bool
}

// identifierPolicy is resource/authorization_servers' policy: no query, no
// fragment.
var identifierPolicy = uriPolicy{}

// locatorPolicy is resource_documentation/resource_metadata's policy: a
// query and a fragment are both permitted.
var locatorPolicy = uriPolicy{allowQuery: true, allowFragment: true}

// requireAbsoluteURI applies §28.2 rules 1 and 2 to one member. It returns
// the parse so a caller that needs the path (§28.3) does not parse twice.
func requireAbsoluteURI(operation, field, raw string, policy uriPolicy) (parsedURI, error) {
	if raw == "" {
		return parsedURI{}, mcpRefuse(operation, field, "must be a non-empty absolute URI")
	}
	parsed, ok := parseAbsoluteURI(raw)
	if !ok {
		return parsedURI{}, mcpRefuse(operation, field, fmt.Sprintf("must be an absolute URI with a scheme and an authority, not %q", raw))
	}
	if parsed.hasQuery && !policy.allowQuery {
		return parsedURI{}, mcpRefuse(operation, field, "must carry no query — §28.3 derives the metadata path from it")
	}
	if parsed.hasFragment && !policy.allowFragment {
		return parsedURI{}, mcpRefuse(operation, field, "must carry no fragment")
	}
	scheme := strings.ToLower(parsed.scheme)
	if scheme == "https" {
		return parsed, nil
	}
	if scheme == "http" && loopbackHosts[strings.ToLower(hostOf(parsed.authority))] {
		return parsed, nil
	}
	return parsedURI{}, mcpRefuse(operation, field, fmt.Sprintf("must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and %q is neither", raw))
}

// ---------------------------------------------------------------------------
// §28.1 / §28.2 — ProtectedResourceMetadata
// ---------------------------------------------------------------------------

// ProtectedResourceMetadataOptions is the input to ProtectedResourceMetadata
// (CONTRACT.md §28.1), in the canonical argument order.
type ProtectedResourceMetadataOptions struct {
	// Resource is the identifier this server publishes for itself — an
	// absolute URI, https (or http on a loopback host), carrying no query
	// and no fragment. A trailing slash is significant.
	Resource string
	// AuthorizationServers is the issuer identifiers of the authorization
	// servers guarding Resource — at least one, no duplicates, each an
	// absolute URI with no query and no fragment.
	AuthorizationServers []string
	// ScopesSupported is the scope tokens this resource server
	// understands, in the caller's order. An empty (but non-nil) slice is
	// accepted and omits the member from the document (§28.2 rule 5).
	ScopesSupported []string
	// BearerMethodsSupported defaults to ["header"] when nil, which is
	// also the only value this contract version accepts (§28.2 rule 6).
	BearerMethodsSupported []string
	// ResourceDocumentation is an optional documentation page for a
	// human. May carry a query and a fragment; omitted from the document
	// when "".
	ResourceDocumentation string
}

// MCPResourceMetadataDocument is the RFC 9728 §2 document, carrying at most
// the members §28.2 permits, in that order, and no others (CONTRACT.md
// §28.2). ScopesSupported and ResourceDocumentation are omitted — never
// emitted empty or null — when the caller supplied none.
type MCPResourceMetadataDocument struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// MCPResourceMetadata is what ProtectedResourceMetadata returns (and what
// middleware.ServeProtectedResourceMetadata echoes back): the document, the
// path it is served at, and the URL that path resolves to.
//
// MetadataURL exists so an integrator feeds a guard's ResourceMetadataURL
// option (middleware.WithResourceMetadataURL /
// middleware.WithRequireResourceMetadataURL) from the value that derived it
// rather than by retyping the string — retyping is how the two come to
// disagree, and a challenge pointing at a document that is not this
// resource server's is worse than no challenge at all.
type MCPResourceMetadata struct {
	Document     MCPResourceMetadataDocument
	MetadataPath string
	MetadataURL  string
}

// ProtectedResourceMetadata builds and validates the RFC 9728
// protected-resource metadata document this server publishes about itself,
// and derives the path and URL it is served at (CONTRACT.md §28.1, §28.2).
//
// Validation happens here and it refuses; it never repairs. Every §28.2
// rule is checked before any route exists and before any request is
// served, and a violation returns *ValidationError (§2's taxonomy — §28
// adds no error type). Nothing is normalised, trimmed, lowercased or
// re-encoded to make a value pass: a value that needs adjusting is a
// configuration mistake an operator fixes in one line, and a helper that
// quietly fixed it would publish a document describing a resource server
// that does not exist.
//
// Nothing in the document may come from a request (§28.2 rule 8). Both
// Resource and AuthorizationServers are configuration; this SDK offers no
// option to build either from a Host header, a Forwarded/X-Forwarded-*
// header or the request URL, because a document assembled from the request
// is a document an attacker can point at an authorization server of their
// choosing — the whole handshake redirected with one header.
func ProtectedResourceMetadata(opts ProtectedResourceMetadataOptions) (MCPResourceMetadata, error) {
	const op = "ProtectedResourceMetadata"

	// Rule 1 + rule 2.
	parsed, err := requireAbsoluteURI(op, "resource", opts.Resource, identifierPolicy)
	if err != nil {
		return MCPResourceMetadata{}, err
	}

	// Rule 3 + rule 4: at least one entry, each an issuer verbatim, no
	// duplicates.
	if len(opts.AuthorizationServers) == 0 {
		return MCPResourceMetadata{}, mcpRefuse(op, "authorization_servers",
			"must name at least one authorization server — a document that names none answers none of the question the client asked")
	}
	seenServers := make(map[string]bool, len(opts.AuthorizationServers))
	authorizationServers := make([]string, 0, len(opts.AuthorizationServers))
	for _, entry := range opts.AuthorizationServers {
		if _, err := requireAbsoluteURI(op, "authorization_servers", entry, identifierPolicy); err != nil {
			return MCPResourceMetadata{}, err
		}
		if seenServers[entry] {
			return MCPResourceMetadata{}, mcpRefuse(op, "authorization_servers", fmt.Sprintf("duplicate entry %q", entry))
		}
		seenServers[entry] = true
		authorizationServers = append(authorizationServers, entry)
	}

	// Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty
	// omits.
	seenScopes := make(map[string]bool, len(opts.ScopesSupported))
	scopesSupported := make([]string, 0, len(opts.ScopesSupported))
	for _, scope := range opts.ScopesSupported {
		if !isAllNQChar(scope) {
			return MCPResourceMetadata{}, mcpRefuse(op, "scopes_supported",
				fmt.Sprintf("%q is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control character, no non-ASCII)", scope))
		}
		if seenScopes[scope] {
			return MCPResourceMetadata{}, mcpRefuse(op, "scopes_supported", fmt.Sprintf("duplicate scope %q", scope))
		}
		seenScopes[scope] = true
		scopesSupported = append(scopesSupported, scope)
	}

	// Rule 6: exactly ["header"]. nil means "use the default", which is
	// also the only accepted value — an explicit empty slice is NOT the
	// default and is refused below like any other wrong value.
	methods := opts.BearerMethodsSupported
	if methods == nil {
		methods = bearerMethodsSupportedDefault
	}
	if len(methods) != 1 || methods[0] != "header" {
		return MCPResourceMetadata{}, mcpRefuse(op, "bearer_methods_supported",
			fmt.Sprintf("must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone, so %v would describe behaviour this SDK does not have", methods))
	}

	// Rule 7: absolute URL, query and fragment permitted, omitted when
	// absent.
	if opts.ResourceDocumentation != "" {
		if _, err := requireAbsoluteURI(op, "resource_documentation", opts.ResourceDocumentation, locatorPolicy); err != nil {
			return MCPResourceMetadata{}, err
		}
	}

	document := MCPResourceMetadataDocument{
		Resource:               opts.Resource,
		AuthorizationServers:   authorizationServers,
		BearerMethodsSupported: []string{"header"},
	}
	if len(scopesSupported) > 0 {
		document.ScopesSupported = scopesSupported
	}
	if opts.ResourceDocumentation != "" {
		document.ResourceDocumentation = opts.ResourceDocumentation
	}

	metadataPath := deriveMetadataPath(parsed.path)
	return MCPResourceMetadata{
		Document:     document,
		MetadataPath: metadataPath,
		MetadataURL:  parsed.scheme + "://" + parsed.authority + metadataPath,
	}, nil
}

// deriveMetadataPath applies §28.3's derivation: RFC 9728 §3.1 inserts the
// well-known segment between the authority and the path. An empty path and
// a bare "/" both reach the root form; anything else is appended, trailing
// slash included — it is part of the identifier a client compares, and two
// resources that differ only by it are two resources.
func deriveMetadataPath(resourcePath string) string {
	if resourcePath == "" || resourcePath == "/" {
		return protectedResourceMetadataPrefix
	}
	return protectedResourceMetadataPrefix + resourcePath
}

// ---------------------------------------------------------------------------
// §28.4 — BearerChallenge
// ---------------------------------------------------------------------------

// BearerChallengeOptions is the input to BearerChallenge (CONTRACT.md
// §28.1, §28.4), in the canonical argument order.
type BearerChallengeOptions struct {
	// ResourceMetadataURL is the document's URL — the one parameter that
	// is always present. May carry a query and a fragment.
	ResourceMetadataURL string
	// Error is one of BearerChallengeErrorInvalidRequest,
	// BearerChallengeErrorInvalidToken or
	// BearerChallengeErrorInsufficientScope, or "" when the request
	// carried no authentication information at all.
	Error string
	// ErrorDescription is a human-readable description, for an
	// application building its OWN challenge for its own 400.
	//
	// The SDK's own guards never set it: expired, not yet valid, wrong
	// tenant, wrong audience, bad signature, alg confusion, an
	// unsatisfiable cnf, a revoked sid — §28.4 makes all of them
	// invalid_token, indistinguishably. Every distinction a 401 draws for
	// an unauthenticated stranger is an oracle (§28.8).
	ErrorDescription string
	// Scope is the scope the route asked for, verbatim — one or more
	// tokens joined by a single space.
	Scope string
}

// BearerChallenge builds the VALUE of a WWW-Authenticate header
// (CONTRACT.md §28.4) — never the whole header line and never a map. The
// caller — usually a guard — sets the header.
//
// Parameters appear in a fixed order — error, error_description, scope,
// resource_metadata — separated by exactly ", ". resource_metadata is
// always present; the other three are omitted when not given.
//
// Every value is quoted and no value is ever escaped. RFC 6750 §3
// restricts each parameter to a character set that cannot contain '"' or
// '\', so a value needing an escape is a value that does not belong in a
// challenge: this function refuses it rather than escaping, truncating or
// stripping it, and returns *ValidationError. A challenge is built from
// the code's own constants and a route's own configuration, so an invalid
// one is a programming error, not a runtime condition to degrade around.
func BearerChallenge(opts BearerChallengeOptions) (string, error) {
	const op = "BearerChallenge"
	var params []string

	if opts.Error != "" {
		switch opts.Error {
		case BearerChallengeErrorInvalidRequest, BearerChallengeErrorInvalidToken, BearerChallengeErrorInsufficientScope:
		default:
			return "", mcpRefuse(op, "error",
				fmt.Sprintf("must be one of invalid_request, invalid_token, insufficient_scope — RFC 6750 §3.1 defines no others, and %q is not among them", opts.Error))
		}
		params = append(params, quotedChallengeParam("error", opts.Error))
	}

	if opts.ErrorDescription != "" {
		if !isAllNQSChar(opts.ErrorDescription) {
			return "", mcpRefuse(op, "error_description",
				`must be one or more NQSCHAR (no '"', no '\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge`)
		}
		params = append(params, quotedChallengeParam("error_description", opts.ErrorDescription))
	}

	if opts.Scope != "" {
		for _, token := range strings.Split(opts.Scope, " ") {
			if !isAllNQChar(token) {
				return "", mcpRefuse(op, "scope",
					fmt.Sprintf("%q is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token", opts.Scope))
			}
		}
		params = append(params, quotedChallengeParam("scope", opts.Scope))
	}

	if _, err := requireAbsoluteURI(op, "resource_metadata", opts.ResourceMetadataURL, locatorPolicy); err != nil {
		return "", err
	}
	if !isAllNQChar(opts.ResourceMetadataURL) {
		return "", mcpRefuse(op, "resource_metadata",
			`must carry no '"', no '\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded`)
	}
	params = append(params, quotedChallengeParam("resource_metadata", opts.ResourceMetadataURL))

	return "Bearer " + strings.Join(params, ", "), nil
}

// quotedChallengeParam formats one WWW-Authenticate parameter. Values
// reaching this point have already been validated to contain no '"' and no
// '\' (NQCHAR/NQSCHAR exclude both), so this is a literal wrap — never an
// escape — matching §28.4's "every value is quoted and no value is ever
// escaped".
func quotedChallengeParam(name, value string) string {
	return name + `="` + value + `"`
}
