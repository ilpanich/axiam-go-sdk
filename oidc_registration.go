package axiam

// RFC 7592 client configuration — CONTRACT.md §28.12 (contract 1.53).
//
// A client that registered itself through `POST /oauth2/register` (RFC 7591)
// receives, once, a `registration_client_uri` and a
// `registration_access_token`. With those two it can read, replace and delete
// ITS OWN registration: ReadClientRegistration, UpdateClientRegistration and
// DeleteClientRegistration.
//
// Four rules shape all three (§28.12.2):
//
//  1. The URI is used verbatim, and only at the configured AXIAM. A URI whose
//     scheme, host or port differs from the client's base URL — or an http URI
//     when the base URL is not http on a loopback host — is refused locally,
//     before any request: the token is a bearer, and a helper that followed a
//     URI to another origin would hand it to whoever wrote the URI.
//  2. The token travels in `Authorization: Bearer` only — never in the query,
//     never in a body.
//  3. It is not the SDK's session. These requests go out on a transport with no
//     cookie jar and no redirect following, carry no SDK access token, no CSRF
//     echo and no adopted credential, and a 401 from them never reaches the §9
//     refresh guard.
//  4. Neither write is retried. An update that reached the server and lost its
//     response has already rotated the token; a delete whose 204 was lost would
//     read 401 on a retry. Only the read follows §16, and never on a 4xx other
//     than 408 or 429.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// serverStatedRegistrationMembers are the members UpdateClientRegistration
// never sends (§28.12.2 rule 4). The first four the server refuses with
// `400 invalid_request` when present; client_secret it never accepts back.
var serverStatedRegistrationMembers = []string{
	"registration_access_token",
	"registration_client_uri",
	"client_secret_expires_at",
	"client_id_issued_at",
	"client_secret",
}

// ClientRegistration is an RFC 7591 §3.2.1 / RFC 7592 §3 client information
// response (CONTRACT.md §28.12.1).
//
// RegistrationAccessToken and ClientSecret are Sensitive (§28.12.4): every fmt
// verb and every JSON rendering of this type shows "[SENSITIVE]" in their
// place.
//
// Every member the server sent that this type does not name is kept in Extra,
// verbatim — RFC 7591 §3.2.1 lets a server add members, and because an update
// is a FULL REPLACEMENT, a member a read returned and an update left out is a
// member the server deletes. Passing a read's result straight to
// UpdateClientRegistration therefore sends it back intact, including the CIBA
// backchannel_* members. A known member of an unexpected JSON type — a
// redirect_uris that is not an array, or an array with an item that is not a
// string — is kept in Extra too, as read, rather than dropped or rewritten; the
// matching field is then nil.
//
// A nil list field means "the read did not carry it": an update does not send
// it, and in particular does not send []. Set a non-nil empty slice to send [].
type ClientRegistration struct {
	// ClientID is the client's client_id.
	ClientID string
	// ClientIDIssuedAt is when the client id was issued (seconds since the
	// epoch). Never sent on an update.
	ClientIDIssuedAt *int64
	// ClientName is the registered display name.
	ClientName *string
	// RedirectURIs are the registered redirect URIs.
	RedirectURIs []string
	// GrantTypes are the registered grant types.
	GrantTypes []string
	// ResponseTypes are the registered response types.
	ResponseTypes []string
	// TokenEndpointAuthMethod is how the client authenticates at the token
	// endpoint. The server refuses an update that changes it.
	TokenEndpointAuthMethod *string
	// Scope is the registered scope, space-separated.
	Scope *string
	// RegistrationClientURI is where this registration is read, replaced and
	// deleted. Never sent on an update.
	RegistrationClientURI *string
	// ClientSecretExpiresAt is when the client secret expires (0 = never).
	// Never sent on an update.
	ClientSecretExpiresAt *int64
	// JWKS is the client's JWK Set, for a private_key_jwt client, verbatim.
	JWKS json.RawMessage
	// JWKSURI is where the client's JWK Set is published.
	JWKSURI *string
	// ClientSecret is present only on the registration response itself, never
	// on a read or an update; "" when absent. Never sent back.
	ClientSecret Sensitive
	// RegistrationAccessToken is present on the registration response and,
	// ROTATED, on every update response; "" on a read. Never sent in a body.
	RegistrationAccessToken Sensitive
	// Extra holds every other member of the response, verbatim.
	Extra map[string]json.RawMessage
}

// UnmarshalJSON decodes a client information response, tolerating unknown
// members (they land in Extra) and refusing only a body that is not a JSON
// object or carries no string client_id.
func (r *ClientRegistration) UnmarshalJSON(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return errors.New("client registration response is not a JSON object")
	}
	var out ClientRegistration
	clientID, ok := takeRegistrationString(members, "client_id")
	if !ok || clientID == nil {
		return errors.New("client registration response carries no client_id")
	}
	out.ClientID = *clientID
	out.ClientIDIssuedAt = takeRegistrationInt(members, "client_id_issued_at")
	out.ClientName, _ = takeRegistrationString(members, "client_name")
	out.RedirectURIs = takeRegistrationList(members, "redirect_uris")
	out.GrantTypes = takeRegistrationList(members, "grant_types")
	out.ResponseTypes = takeRegistrationList(members, "response_types")
	out.TokenEndpointAuthMethod, _ = takeRegistrationString(members, "token_endpoint_auth_method")
	out.Scope, _ = takeRegistrationString(members, "scope")
	out.RegistrationClientURI, _ = takeRegistrationString(members, "registration_client_uri")
	out.ClientSecretExpiresAt = takeRegistrationInt(members, "client_secret_expires_at")
	out.JWKSURI, _ = takeRegistrationString(members, "jwks_uri")
	if raw, present := members["jwks"]; present {
		delete(members, "jwks")
		if !isJSONNull(raw) {
			out.JWKS = raw
		}
	}
	if secret, _ := takeRegistrationString(members, "client_secret"); secret != nil {
		out.ClientSecret = Sensitive(*secret)
	}
	if token, _ := takeRegistrationString(members, "registration_access_token"); token != nil {
		out.RegistrationAccessToken = Sensitive(*token)
	}
	if len(members) > 0 {
		out.Extra = members
	}
	*r = out
	return nil
}

// MarshalJSON renders the registration in its wire shape, Extra merged in, for
// logs and debugging — with ClientSecret and RegistrationAccessToken rendered
// as "[SENSITIVE]". It is NOT the update body: UpdateClientRegistration builds
// that itself and never sends either secret.
func (r ClientRegistration) MarshalJSON() ([]byte, error) {
	body := r.wireMembers()
	if r.ClientSecret != "" {
		body["client_secret"] = json.RawMessage(`"` + redacted + `"`)
	}
	if r.RegistrationAccessToken != "" {
		body["registration_access_token"] = json.RawMessage(`"` + redacted + `"`)
	}
	putRawInt(body, "client_id_issued_at", r.ClientIDIssuedAt)
	putRawString(body, "registration_client_uri", r.RegistrationClientURI)
	putRawInt(body, "client_secret_expires_at", r.ClientSecretExpiresAt)
	return json.Marshal(body)
}

// wireMembers is Extra plus the members an update carries.
func (r ClientRegistration) wireMembers() map[string]json.RawMessage {
	body := make(map[string]json.RawMessage, len(r.Extra)+10)
	for k, v := range r.Extra {
		body[k] = v
	}
	putRawString(body, "client_id", &r.ClientID)
	putRawString(body, "client_name", r.ClientName)
	// A list is sent only when the read carried it (§28.12.2 rule 4, §34.2
	// P12.4): nil is "the read lacked it", and no list becomes [] for that. A
	// list of unexpected shape never reached these fields — takeRegistrationList
	// left it in Extra, copied above — so it goes back exactly as read.
	putRawList(body, "redirect_uris", r.RedirectURIs)
	putRawList(body, "grant_types", r.GrantTypes)
	putRawList(body, "response_types", r.ResponseTypes)
	putRawString(body, "token_endpoint_auth_method", r.TokenEndpointAuthMethod)
	putRawString(body, "scope", r.Scope)
	if len(r.JWKS) > 0 {
		body["jwks"] = r.JWKS
	}
	putRawString(body, "jwks_uri", r.JWKSURI)
	return body
}

// updateBody is the RFC 7592 §2.2 replacement body: every member but the five
// the server states (§28.12.2 rule 4), with client_id set to this
// registration's own.
func (r ClientRegistration) updateBody() map[string]json.RawMessage {
	body := r.wireMembers()
	for _, member := range serverStatedRegistrationMembers {
		delete(body, member)
	}
	putRawString(body, "client_id", &r.ClientID)
	return body
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// takeRegistrationString removes key and returns its string value. A member of
// another JSON type is put back (it stays in Extra) and reported as absent; ok
// is false only for that mistyped case.
func takeRegistrationString(members map[string]json.RawMessage, key string) (*string, bool) {
	raw, present := members[key]
	if !present {
		return nil, true
	}
	if isJSONNull(raw) {
		delete(members, key)
		return nil, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	delete(members, key)
	return &s, true
}

// takeRegistrationInt is takeRegistrationString for an integer member.
func takeRegistrationInt(members map[string]json.RawMessage, key string) *int64 {
	raw, present := members[key]
	if !present {
		return nil
	}
	if isJSONNull(raw) {
		delete(members, key)
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil
	}
	delete(members, key)
	return &n
}

// takeRegistrationList removes key and returns its string items. A member that
// is not an array, or an array with an item that is not a string, is put back
// (it stays in Extra, verbatim) and reported as absent: an update sends it as
// read rather than dropping the item (§34.2 P12.4). An empty array returns an
// empty non-nil slice, which is how "present and empty" differs from "absent"
// (nil).
func takeRegistrationList(members map[string]json.RawMessage, key string) []string {
	raw, present := members[key]
	if !present {
		return nil
	}
	if isJSONNull(raw) {
		delete(members, key)
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		var s string
		if json.Unmarshal(item, &s) != nil {
			return nil // unexpected shape: stays in members, i.e. in Extra
		}
		out = append(out, s)
	}
	delete(members, key)
	return out
}

func putRawString(body map[string]json.RawMessage, key string, value *string) {
	if value == nil {
		return
	}
	encoded, _ := json.Marshal(*value)
	body[key] = encoded
}

func putRawInt(body map[string]json.RawMessage, key string, value *int64) {
	if value == nil {
		return
	}
	body[key] = json.RawMessage(fmt.Sprintf("%d", *value))
}

// putRawList sets key to items, or leaves body untouched when items is nil —
// the read lacked the member, so the update does not invent it.
func putRawList(body map[string]json.RawMessage, key string, items []string) {
	if items == nil {
		return
	}
	encoded, _ := json.Marshal(items)
	body[key] = encoded
}

// localRefusal builds the SDK's local pre-request refusal: a *ValidationError,
// the same sub-type the §27 surface and §28's helpers raise (§28.7's Go row).
// Status is 400 — the code the server would answer for the same mistake —
// although no request was sent.
func localRefusal(operation, field, message string) *ValidationError {
	return &ValidationError{
		Operation: operation,
		Status:    http.StatusBadRequest,
		Message:   fmt.Sprintf("%s: %s: %s", operation, field, message),
		Fields:    []FieldError{{Field: field, Message: message}},
	}
}

// isLoopbackHost reports whether host (already lower-cased, unbracketed) is
// one of the three loopback names §28.12.2 rule 1 lets an http base URL use.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// originOf is (scheme, host, port-or-default), lower-cased.
func originOf(u *url.URL) (string, string, string) {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, strings.ToLower(u.Hostname()), port
}

// checkSameOrigin applies §28.12.2 rule 1 (and §32.7's equivalent): rawURI
// must be an absolute http(s) URL at the client's own origin, and http only
// when the base URL is itself http on a loopback host.
//
// The refusal names no part of the URI: it is caller input, and an error
// message is the one most often logged.
func (c *Client) checkSameOrigin(operation, field, rawURI string) (*url.URL, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, localRefusal(operation, field, "not an absolute URL (CONTRACT.md §28.12.2 rule 1)")
	}
	scheme, host, port := originOf(parsed)
	if scheme != "https" && scheme != "http" {
		return nil, localRefusal(operation, field, "must be an https URL (CONTRACT.md §28.12.2 rule 1)")
	}
	baseScheme, baseHost, basePort := originOf(c.baseURL)
	if scheme != baseScheme || host != baseHost || port != basePort {
		return nil, localRefusal(operation, field,
			"not at the configured AXIAM origin: scheme, host and port must match the client's base URL (CONTRACT.md §28.12.2 rule 1)")
	}
	if scheme == "http" && !isLoopbackHost(baseHost) {
		return nil, localRefusal(operation, field,
			"must be https unless the base URL is http on a loopback host (CONTRACT.md §28.12.2 rule 1)")
	}
	return parsed, nil
}

// bareHTTPClient is this Client's transport — its §6 TLS policy and timeout —
// with NO cookie jar and NO redirect following. It carries a credential that
// is not the SDK's session (§28.12.2 rule 3, §32.7's poll): nothing from the
// jar may ride along, and a redirect must not carry the bearer anywhere.
func (c *Client) bareHTTPClient() *http.Client {
	clone := *c.httpc
	clone.Jar = nil
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

// statusIsRetryable is §16.3's table for a status: 408, 429 and 5xx.
func statusIsRetryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

// errStopRetry ends a §16 loop on a decisive answer. It is not a *NetworkError,
// so retryReadOnly returns it at once; the caller substitutes the real error.
var errStopRetry = errors.New("axiam: decisive answer, not retried")

// oauth2ErrorAnyStatus maps a failed /oauth2/* response per §2's /oauth2 row
// as §28.12.3 and §33.4 state it: a body with a non-empty `error` member is an
// *OAuthProtocolError at ANY status (error_description optional); anything else
// maps by status, a *NetworkError carrying the Retry-After hint.
func oauth2ErrorAnyStatus(resp *http.Response, operation string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var wire oauth2ErrorResponseWire
	if err := json.Unmarshal(body, &wire); err == nil && wire.Error != "" {
		message := wire.Error
		if wire.ErrorDescription != "" {
			message += ": " + wire.ErrorDescription
		}
		return &OAuthProtocolError{
			AuthError:        AuthError{Message: message},
			ErrorCode:        wire.Error,
			ErrorDescription: wire.ErrorDescription,
		}
	}
	err := errorFromHTTPStatus(resp.StatusCode, fmt.Sprintf("%s failed with HTTP %d", operation, resp.StatusCode), resp, nil)
	if netErr, ok := err.(*NetworkError); ok {
		netErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return err
}

// ReadClientRegistration issues `GET registration_client_uri` (RFC 7592 §2.1,
// CONTRACT.md §28.12) — read this client's registration.
//
// The result carries neither the token nor the client secret: the server never
// returns them on a read. It does carry every member an update needs, so the
// usual update is "read, change a field, update".
//
// Retried per §16 on a transport failure, a 5xx, a 408 or a 429 (a read is
// safe to repeat) — never on another 4xx. A `401 invalid_token` — an unknown
// client, a wrong or rotated-away token, another tenant's client, a client
// with no token: the server never says which — is an *OAuthProtocolError, and
// never refreshes the SDK's session.
//
// A URI at another origin is refused with a local *ValidationError before any
// request (§28.12.2 rule 1).
func (c *Client) ReadClientRegistration(ctx context.Context, registrationClientURI string, registrationAccessToken Sensitive) (ClientRegistration, error) {
	const operation = "read_client_registration"
	if err := c.ensureOpen(); err != nil {
		return ClientRegistration{}, err
	}
	target, err := c.checkSameOrigin(operation, "registration_client_uri", registrationClientURI)
	if err != nil {
		return ClientRegistration{}, err
	}
	var (
		result   ClientRegistration
		decisive error
	)
	retryErr := c.retryReadOnly(ctx, operation, func(ctx context.Context, _ int) error {
		got, status, err := c.sendRegistration(ctx, operation, http.MethodGet, target, registrationAccessToken, nil)
		if err == nil {
			result = got
			return nil
		}
		if status != 0 && !statusIsRetryable(status) {
			decisive = err
			return errStopRetry
		}
		return err
	})
	if decisive != nil {
		return ClientRegistration{}, decisive
	}
	if retryErr != nil {
		return ClientRegistration{}, retryErr
	}
	return result, nil
}

// UpdateClientRegistration issues `PUT registration_client_uri` (RFC 7592
// §2.2, CONTRACT.md §28.12) — REPLACE this client's registration, and receive
// a ROTATED token.
//
// metadata is the WHOLE registration: a member it omits is a member the server
// deletes. Start from ReadClientRegistration's result, which carries every
// member (JWKS / JWKSURI and Extra included), and change what you mean to
// change. The SDK sets client_id to metadata.ClientID and never sends
// registration_access_token, registration_client_uri,
// client_secret_expires_at, client_id_issued_at or client_secret.
//
// PERSIST THE RETURNED RegistrationAccessToken BEFORE DOING ANYTHING ELSE.
// From the moment the server answers, it is the only valid token: the one you
// presented is dead for every operation.
//
// NEVER RETRIED — not on a transport error, not on a 5xx. An update that
// reached the server and lost its response has already rotated the token;
// repeating it with the old one is a 401 that locks you out of your own
// registration. On a lost answer, read the registration with the token you
// hold: a 401 means the update landed.
func (c *Client) UpdateClientRegistration(ctx context.Context, registrationClientURI string, registrationAccessToken Sensitive, metadata ClientRegistration) (ClientRegistration, error) {
	const operation = "update_client_registration"
	if err := c.ensureOpen(); err != nil {
		return ClientRegistration{}, err
	}
	target, err := c.checkSameOrigin(operation, "registration_client_uri", registrationClientURI)
	if err != nil {
		return ClientRegistration{}, err
	}
	body, err := json.Marshal(metadata.updateBody())
	if err != nil {
		return ClientRegistration{}, localRefusal(operation, "metadata", "could not be encoded as JSON")
	}
	got, _, err := c.sendRegistration(ctx, operation, http.MethodPut, target, registrationAccessToken, body)
	return got, err
}

// DeleteClientRegistration issues `DELETE registration_client_uri` (RFC 7592
// §2.3, CONTRACT.md §28.12) — delete this client's registration. A 204 returns
// nil.
//
// NEVER RETRIED: a retry after a lost 204 would read 401 and report a
// successful deletion as a failure.
func (c *Client) DeleteClientRegistration(ctx context.Context, registrationClientURI string, registrationAccessToken Sensitive) error {
	const operation = "delete_client_registration"
	if err := c.ensureOpen(); err != nil {
		return err
	}
	target, err := c.checkSameOrigin(operation, "registration_client_uri", registrationClientURI)
	if err != nil {
		return err
	}
	_, _, err = c.sendRegistration(ctx, operation, http.MethodDelete, target, registrationAccessToken, nil)
	return err
}

// sendRegistration performs exactly one RFC 7592 request on the bare
// transport. status is the HTTP status of a failed response, 0 for a
// transport failure. A DELETE's success decodes nothing.
func (c *Client) sendRegistration(ctx context.Context, operation, method string, target *url.URL, token Sensitive, body []byte) (ClientRegistration, int, error) {
	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), payload)
	if err != nil {
		return ClientRegistration{}, 0, &NetworkError{Message: fmt.Sprintf("%s: failed to build the request", operation)}
	}
	req.Header.Set("Authorization", "Bearer "+token.expose())
	if method != http.MethodDelete {
		req.Header.Set("Accept", "application/json")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.bareHTTPClient().Do(req)
	if err != nil {
		// The transport error's text can carry the URL; the URL carries no
		// token (rule 2), but the message stays generic all the same.
		return ClientRegistration{}, 0, newNetworkError(operation+": request failed", nil, nil)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ClientRegistration{}, resp.StatusCode, oauth2ErrorAnyStatus(resp, operation)
	}
	if method == http.MethodDelete {
		_, _ = io.Copy(io.Discard, resp.Body)
		return ClientRegistration{}, 0, nil
	}
	var out ClientRegistration
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ClientRegistration{}, 0, &NetworkError{Message: fmt.Sprintf("%s: could not decode the response: %v", operation, err)}
	}
	return out, 0, nil
}
