package axiam

// CIBA — client-initiated backchannel authentication, CONTRACT.md §33
// (contract 1.58; CIBA Core 1.0, poll and ping modes).
//
// A client that already knows whom it wants to authenticate asks AXIAM to
// authenticate that user ON ANOTHER DEVICE; AXIAM notifies the user, who
// approves or refuses on the console. The client then collects the tokens at
// the token endpoint — by polling, or once after AXIAM pings it.
//
//   - CibaInitiate: POST /oauth2/bc-authorize. NEVER RETRIED.
//   - CibaPoll: one token request with grant_type=urn:openid:params:grant-type:ciba.
//   - CibaAwait: polls to a terminal outcome, honouring interval and slow_down.
//   - CibaHandlePing: verifies a ping's bearer and returns its auth_req_id; no I/O.
//
// Two things a caller must not read into a success:
//
//   - A successful CibaInitiate PROVES NOTHING ABOUT THE USER (§33.3 rule 4).
//     AXIAM answers a hint that names nobody, a locked user and a real one
//     identically, and the only signal that a user did not answer is
//     expired_token. Nothing here reports that a user "exists" or "was
//     notified".
//   - A ping says the request was DECIDED, NEVER HOW (§33.2). Call CibaPoll
//     after answering the ping; the outcome — tokens, access_denied or
//     expired_token — comes from the token endpoint.
//
// The client always authenticates, by the credential this SDK was built with
// (client_secret_post via WithOidcClientSecret, or the §6.1 client certificate
// for a tls_client_auth client); a client built with neither is refused
// locally. auth_req_id, client_notification_token, the signing key and the
// signed request are Sensitive (§33.5).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// CibaGrantType is the grant_type of the CIBA token request (CIBA Core §10.1).
	CibaGrantType = "urn:openid:params:grant-type:ciba"

	// DefaultCibaInterval is the polling interval used when the initiate
	// response carries none (§33.7 rule 2). An SDK MUST NOT hard-code a faster
	// floor.
	DefaultCibaInterval = 5 * time.Second

	// CibaSlowDownIncrement is added to the interval per slow_down,
	// permanently and cumulatively (§33.7 rule 3).
	CibaSlowDownIncrement = 5 * time.Second

	// cibaSignedRequestLifetime is the lifetime of a signed request this SDK
	// mints: five minutes, inside the server's sixty-minute bound on
	// exp - nbf (§33.2).
	cibaSignedRequestLifetime = 300 * time.Second
)

// CibaDelivery is how the client receives the outcome, as it registered.
type CibaDelivery string

const (
	// CibaDeliveryPoll is poll mode — the zero value's meaning too.
	CibaDeliveryPoll CibaDelivery = "poll"
	// CibaDeliveryPing is ping mode: AXIAM pings the client's registered
	// notification endpoint presenting ClientNotificationToken, and the client
	// then polls once.
	CibaDeliveryPing CibaDelivery = "ping"
)

// CibaSigningAlg is a signature algorithm a signed CIBA request may use
// (§33.2): the one the client registered as
// backchannel_authentication_request_signing_alg.
type CibaSigningAlg string

const (
	// CibaSigningPS256 is RSASSA-PSS with SHA-256 (an RSA key of 2048 bits or more).
	CibaSigningPS256 CibaSigningAlg = "PS256"
	// CibaSigningES256 is ECDSA on P-256 with SHA-256.
	CibaSigningES256 CibaSigningAlg = "ES256"
	// CibaSigningEdDSA is Ed25519.
	CibaSigningEdDSA CibaSigningAlg = "EdDSA"
)

// CibaRequestSigner is the key and algorithm of the signed request form (§33.2,
// CIBA Core §7.1.1). Both are the caller's: there is no default for either,
// and the SDK signs under exactly the algorithm given. Build one with
// NewCibaRequestSigner or NewCibaRequestSignerFromPEM, which refuse a key that
// cannot sign under the algorithm before any request.
//
// The key is never rendered: every fmt verb shows the algorithm and kid, and
// "[SENSITIVE]" in the key's place.
type CibaRequestSigner struct {
	alg CibaSigningAlg
	key crypto.Signer
	kid string
}

// NewCibaRequestSigner builds a signer from a private key (an
// ed25519.PrivateKey, *ecdsa.PrivateKey, *rsa.PrivateKey, or any crypto.Signer
// backed by one — an HSM handle included) and the algorithm it signs under. kid
// is put in the JWS header when non-empty.
//
// A local *ValidationError, before any request, when alg is not one of the
// three, or key is nil, of another type, or fails a probe signature.
func NewCibaRequestSigner(alg CibaSigningAlg, key crypto.Signer, kid string) (*CibaRequestSigner, error) {
	refuse := func(why string) (*CibaRequestSigner, error) {
		return nil, localRefusal("ciba_initiate", "signing_key", why+" (CONTRACT.md §33.2)")
	}
	if key == nil {
		return refuse("no signing key was given")
	}
	switch alg {
	case CibaSigningEdDSA:
		if _, ok := key.Public().(ed25519.PublicKey); !ok {
			return refuse("an EdDSA signer needs an Ed25519 key")
		}
	case CibaSigningES256:
		pub, ok := key.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return refuse("an ES256 signer needs an ECDSA P-256 key")
		}
	case CibaSigningPS256:
		pub, ok := key.Public().(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return refuse("a PS256 signer needs an RSA key of 2048 bits or more")
		}
	default:
		return refuse("the algorithm must be PS256, ES256 or EdDSA")
	}
	signer := &CibaRequestSigner{alg: alg, key: key, kid: kid}
	// A key of the right type is not yet a key that signs: prove it does.
	if _, err := signer.sign([]byte("axiam-ciba-probe")); err != nil {
		return refuse("the key failed a probe signature")
	}
	return signer, nil
}

// NewCibaRequestSignerFromPEM is NewCibaRequestSigner for a PEM private key:
// PKCS#8 ("PRIVATE KEY") for any of the three, PKCS#1 ("RSA PRIVATE KEY") or
// SEC 1 ("EC PRIVATE KEY") for RSA and ECDSA. The PEM is Sensitive; it is
// parsed here and not kept.
func NewCibaRequestSignerFromPEM(alg CibaSigningAlg, keyPEM Sensitive, kid string) (*CibaRequestSigner, error) {
	block, _ := pem.Decode([]byte(keyPEM.expose()))
	if block == nil {
		return nil, localRefusal("ciba_initiate", "signing_key", "the PEM holds no private key (CONTRACT.md §33.2)")
	}
	var parsed any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	signer, ok := parsed.(crypto.Signer)
	if err != nil || !ok {
		return nil, localRefusal("ciba_initiate", "signing_key", "the PEM holds no usable private key (CONTRACT.md §33.2)")
	}
	return NewCibaRequestSigner(alg, signer, kid)
}

// Alg is the algorithm this signer signs under.
func (s *CibaRequestSigner) Alg() CibaSigningAlg { return s.alg }

// String renders the algorithm and kid, never the key.
func (s *CibaRequestSigner) String() string {
	if s == nil {
		return "CibaRequestSigner(nil)"
	}
	return fmt.Sprintf("CibaRequestSigner{alg: %s, kid: %q, key: %s}", s.alg, s.kid, redacted)
}

// Format makes every fmt verb use String, so no verb reaches the key.
func (s *CibaRequestSigner) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// GoString covers %#v.
func (s *CibaRequestSigner) GoString() string { return s.String() }

// MarshalJSON renders the algorithm and kid, never the key.
func (s *CibaRequestSigner) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"alg": string(s.alg), "kid": s.kid, "key": redacted})
}

// sign is the JWS signature over input under s.alg (RFC 7518 §3.4, §3.5;
// RFC 8037 §3.1).
func (s *CibaRequestSigner) sign(input []byte) ([]byte, error) {
	switch s.alg {
	case CibaSigningEdDSA:
		return s.key.Sign(rand.Reader, input, crypto.Hash(0))
	case CibaSigningES256:
		digest := sha256.Sum256(input)
		der, err := s.key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		var parsed struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &parsed); err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		parsed.R.FillBytes(out[:32])
		parsed.S.FillBytes(out[32:])
		return out, nil
	default: // CibaSigningPS256 — the constructor admits nothing else.
		digest := sha256.Sum256(input)
		return s.key.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	}
}

// CibaInitiateParams are CibaInitiate's arguments (§33.2 CibaInitiateRequest).
//
// BindingMessage and LoginHint can be personal data: the SDK never logs them.
// There is no member for user_code, login_hint_token or request_uri — AXIAM
// refuses each (§33.3 rule 3) — and none for extra form parameters.
type CibaInitiateParams struct {
	// Scope is space-separated and must include openid. Required.
	Scope string
	// LoginHint names the user: a username, then an e-mail address, within the
	// tenant. Exactly one of LoginHint and IDTokenHint; both or neither is a
	// local *ValidationError.
	LoginHint string
	// IDTokenHint is an ID token this deployment issued to this client.
	IDTokenHint string
	// BindingMessage is shown to the user on the approval page — what lets them
	// tell the request they started from one an attacker did. Required for a
	// fapi2 client. Not sent when empty.
	BindingMessage string
	// RequestedExpiry is the requested lifetime in seconds (the server accepts
	// 30–600; absent means 300). Not sent when zero.
	RequestedExpiry int
	// AcrValues is space-separated. Not sent when empty.
	AcrValues string
	// Resource is an RFC 8707 resource indicator. Not sent when empty.
	Resource string
	// Delivery is the registered mode: CibaDeliveryPoll (or empty) or
	// CibaDeliveryPing.
	Delivery CibaDelivery
	// ClientNotificationToken is the bearer AXIAM presents at the ping; keep it
	// to check the ping with CibaHandlePing. Required in ping mode, refused in
	// poll mode. Never returned by AXIAM.
	ClientNotificationToken Sensitive
	// Signer, when set, sends the request as one signed JWT (`request`) —
	// required of a client that registered a signing algorithm, refused by the
	// server from one that did not.
	Signer *CibaRequestSigner
	// TenantID supplies the tenant_id query parameter (§12.1 note 2).
	TenantID string
	// Configuration is a pre-fetched discovery document; fetched when nil.
	Configuration *OidcConfiguration
}

// CibaInitiateResponse is §33.2's CibaInitiateResponse.
type CibaInitiateResponse struct {
	// AuthReqID is the request's id at the token endpoint — a bearer
	// credential for the grant (§33.5). Never parse or length-check it.
	AuthReqID Sensitive
	// ExpiresIn is the request's lifetime in seconds — authoritative (§33.7
	// rule 4).
	ExpiresIn int
	// Interval is the minimum seconds between token requests: the response's
	// value, or 5 when it was absent or zero.
	Interval int
	// ReceivedAt is when the response was received; CibaAwait's deadline is
	// ReceivedAt + ExpiresIn.
	ReceivedAt time.Time
}

type cibaInitiateResponseWire struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// CibaPollParams are CibaPoll's arguments.
type CibaPollParams struct {
	// AuthReqID is from CibaInitiateResponse or a ping.
	AuthReqID Sensitive
	// TenantID supplies the tenant_id query parameter.
	TenantID string
	// Configuration is a pre-fetched discovery document.
	Configuration *OidcConfiguration
}

// CibaClock is what CibaAwait waits on — injectable so its schedule is testable
// without sleeping (§33.8 tests 6 and 7).
type CibaClock interface {
	// Now is the current time.
	Now() time.Time
	// Sleep waits d, or returns ctx's error when it ends first.
	Sleep(ctx context.Context, d time.Duration) error
}

type systemCibaClock struct{}

func (systemCibaClock) Now() time.Time { return time.Now() }

func (systemCibaClock) Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// CibaAwaitParams are CibaAwait's arguments.
type CibaAwaitParams struct {
	// TenantID supplies the tenant_id query parameter.
	TenantID string
	// Configuration is a pre-fetched discovery document; fetched once when nil.
	Configuration *OidcConfiguration
	// Clock is what the loop waits on; nil is the system clock.
	Clock CibaClock
	// AdoptAsCredential mirrors DeviceLoginParams and
	// LoginClientCredentialsParams: when true, the issued access token becomes
	// this client's Authorization header. The SDK's one adoption posture, not
	// a second one (§33.1).
	AdoptAsCredential bool
}

// cibaClientAuth is the client's credential for these calls: client_id plus
// client_secret (client_secret_post), or client_id alone when the transport
// presents the §6.1 certificate (tls_client_auth). Neither is a local
// *AuthError: a CIBA client is never public (§33.1).
func (c *Client) cibaClientAuth(operation string) (url.Values, error) {
	if c.session.oidc.clientID == "" {
		return nil, &AuthError{Message: operation + " requires a client_id: construct the Client with WithOidcClientID (CONTRACT.md §33.1)"}
	}
	if c.session.oidc.clientSecret == "" && !c.presentsClientCertificate {
		return nil, &AuthError{Message: operation + " requires client authentication — a CIBA client is never public: construct the Client with WithOidcClientSecret or a §6.1 client certificate (CONTRACT.md §33.1)"}
	}
	form := url.Values{}
	form.Set("client_id", c.session.oidc.clientID)
	c.appendOidcClientSecret(form)
	return form, nil
}

// cibaMembers is the authentication request's members, exactly those set.
// requested_expiry is a string here (the form) and a number in a signed JWT.
func cibaMembers(params CibaInitiateParams) map[string]any {
	members := map[string]any{"scope": params.Scope}
	if params.LoginHint != "" {
		members["login_hint"] = params.LoginHint
	}
	if params.IDTokenHint != "" {
		members["id_token_hint"] = params.IDTokenHint
	}
	if params.BindingMessage != "" {
		members["binding_message"] = params.BindingMessage
	}
	if params.RequestedExpiry != 0 {
		members["requested_expiry"] = params.RequestedExpiry
	}
	if params.AcrValues != "" {
		members["acr_values"] = params.AcrValues
	}
	if params.Resource != "" {
		members["resource"] = params.Resource
	}
	if params.Delivery == CibaDeliveryPing {
		members["client_notification_token"] = params.ClientNotificationToken.expose()
	}
	return members
}

func checkCibaInitiate(params CibaInitiateParams) error {
	const operation = "ciba_initiate"
	if (params.LoginHint == "") == (params.IDTokenHint == "") {
		return localRefusal(operation, "login_hint",
			"set exactly one of login_hint and id_token_hint (CONTRACT.md §33.2)")
	}
	switch params.Delivery {
	case "", CibaDeliveryPoll:
		if params.ClientNotificationToken != "" {
			return localRefusal(operation, "client_notification_token",
				"a client_notification_token belongs to a ping-mode request; set Delivery to CibaDeliveryPing (CONTRACT.md §33.2)")
		}
	case CibaDeliveryPing:
		if params.ClientNotificationToken == "" {
			return localRefusal(operation, "client_notification_token",
				"a ping-mode request needs a client_notification_token: without one AXIAM has nothing to ping with (CONTRACT.md §33.2)")
		}
	default:
		return localRefusal(operation, "delivery", "must be poll or ping — AXIAM offers no push mode (CONTRACT.md §33.9)")
	}
	return nil
}

// cibaSignedRequest is the CIBA Core §7.1.1 signed request: every member inside
// the JWT, plus iss, aud, iat, nbf, exp and a fresh jti.
func cibaSignedRequest(params CibaInitiateParams, clientID, issuer string) (Sensitive, error) {
	claims := cibaMembers(params)
	now := time.Now().Unix()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", &NetworkError{Message: "ciba_initiate: no randomness for the signed request's jti"}
	}
	claims["iss"] = clientID
	claims["aud"] = issuer
	claims["iat"] = now
	claims["nbf"] = now
	claims["exp"] = now + int64(cibaSignedRequestLifetime/time.Second)
	claims["jti"] = base64.RawURLEncoding.EncodeToString(jti)
	header := map[string]string{"alg": string(params.Signer.alg)}
	if params.Signer.kid != "" {
		header["kid"] = params.Signer.kid
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", localRefusal("ciba_initiate", "request", "could not be encoded")
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature, err := params.Signer.sign([]byte(input))
	if err != nil {
		return "", localRefusal("ciba_initiate", "signing_key", "the signed request could not be signed with the given key")
	}
	return Sensitive(input + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

// CibaInitiate issues POST /oauth2/bc-authorize (CIBA Core §7, CONTRACT.md
// §33.1) — ask AXIAM to authenticate a user on another device.
//
// The endpoint is the discovery document's backchannel_authentication_endpoint
// (its mtls_endpoint_aliases entry on a call presenting a client certificate);
// a document without one is a local *AuthError, never a concatenated URL. The
// body is form-encoded with exactly the members set — or, with a Signer, only
// client authentication and `request` — and tenant_id travels in the query.
//
// NEVER RETRIED — not on a transport error, a 5xx or a 429 (§33.7 rule 1):
// every accepted call stores a request and may notify a person. On a lost
// answer, let it expire and ask again deliberately.
//
// A success proves nothing about the user (§33.3 rule 4). The server's
// refusals are *OAuthProtocolErrors at any status — invalid_binding_message
// carries the server's ErrorDescription; a 429's rate_limit_exceeded too.
func (c *Client) CibaInitiate(ctx context.Context, params CibaInitiateParams) (CibaInitiateResponse, error) {
	const operation = "ciba_initiate"
	if err := c.ensureOpen(); err != nil {
		return CibaInitiateResponse{}, err
	}
	form, err := c.cibaClientAuth(operation)
	if err != nil {
		return CibaInitiateResponse{}, err
	}
	if err := checkCibaInitiate(params); err != nil {
		return CibaInitiateResponse{}, err
	}
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return CibaInitiateResponse{}, err
	}
	endpoint, err := c.preferredEndpoint(&configuration,
		func(a *MtlsEndpointAliases) string { return a.BackchannelAuthenticationEndpoint },
		configuration.BackchannelAuthenticationEndpoint)
	if err != nil {
		return CibaInitiateResponse{}, err
	}
	if endpoint == "" {
		return CibaInitiateResponse{}, &AuthError{Message: "the authorization server's discovery document advertises no backchannel_authentication_endpoint: this server does not support CIBA (CONTRACT.md §33.1)"}
	}
	target, err := c.oidcEndpointURL(endpoint, params.TenantID)
	if err != nil {
		return CibaInitiateResponse{}, err
	}

	if params.Signer != nil {
		request, err := cibaSignedRequest(params, c.session.oidc.clientID, configuration.Issuer)
		if err != nil {
			return CibaInitiateResponse{}, err
		}
		form.Set("request", request.expose())
	} else {
		for k, v := range cibaMembers(params) {
			switch value := v.(type) {
			case int:
				form.Set(k, strconv.Itoa(value))
			default:
				form.Set(k, fmt.Sprint(value))
			}
		}
	}

	resp, err := c.postCibaForm(ctx, operation, target, form)
	if err != nil {
		return CibaInitiateResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CibaInitiateResponse{}, oauth2ErrorAnyStatus(resp, operation)
	}
	var wire cibaInitiateResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil || wire.AuthReqID == "" {
		return CibaInitiateResponse{}, &NetworkError{Message: operation + ": the response is not a CibaInitiateResponse"}
	}
	interval := wire.Interval
	if interval <= 0 {
		interval = int(DefaultCibaInterval / time.Second)
	}
	return CibaInitiateResponse{
		AuthReqID:  Sensitive(wire.AuthReqID),
		ExpiresIn:  wire.ExpiresIn,
		Interval:   interval,
		ReceivedAt: time.Now(),
	}, nil
}

// postCibaForm sends one form POST through the SDK's request path (§12.1: the
// X-Tenant-ID header, the TLS transport). A transport failure is a
// *NetworkError naming no part of the form.
func (c *Client) postCibaForm(ctx context.Context, operation, target string, form url.Values) (*http.Response, error) {
	req, err := c.newAbsoluteRequest(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, newNetworkError(operation+": request failed", nil, nil)
	}
	return resp, nil
}

// CibaPoll issues ONE POST /oauth2/token with
// grant_type=urn:openid:params:grant-type:ciba (CIBA Core §10.1, CONTRACT.md
// §33.1).
//
// The answers of §33.3 rule 6 surface as *OAuthProtocolError:
// authorization_pending and slow_down (non-terminal), access_denied and
// expired_token (terminal and distinct — errors.Is(err, ErrAccessDenied),
// errors.Is(err, ErrExpiredToken)), invalid_grant. None of them is retried.
// A transport failure, a 5xx, a 408 or a bodiless 429 is retried per §16
// within the call; any other 4xx is not.
//
// STORE THE RETURNED TOKENS BEFORE ANYTHING ELSE: a request is redeemed once,
// and a second CibaPoll for it is invalid_grant (§33.7 rule 7). The ID token
// is validated as for every other grant (no nonce).
func (c *Client) CibaPoll(ctx context.Context, params CibaPollParams) (OidcTokenSet, error) {
	set, _, err := c.cibaPoll(ctx, params)
	return set, err
}

// cibaPoll is CibaPoll, also reporting whether a failure is transient for the
// CibaAwait loop: a transport failure or retryable status that outlived §16.
func (c *Client) cibaPoll(ctx context.Context, params CibaPollParams) (OidcTokenSet, bool, error) {
	const operation = "ciba_poll"
	if err := c.ensureOpen(); err != nil {
		return OidcTokenSet{}, false, err
	}
	form, err := c.cibaClientAuth(operation)
	if err != nil {
		return OidcTokenSet{}, false, err
	}
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, false, err
	}
	endpoint, err := c.preferredEndpoint(&configuration,
		func(a *MtlsEndpointAliases) string { return a.TokenEndpoint },
		configuration.TokenEndpoint)
	if err != nil {
		return OidcTokenSet{}, false, err
	}
	target, err := c.oidcEndpointURL(endpoint, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, false, err
	}
	form.Set("grant_type", CibaGrantType)
	form.Set("auth_req_id", params.AuthReqID.expose())

	var (
		wire     tokenResponseWire
		decisive error
	)
	retryErr := c.retryReadOnly(ctx, operation, func(ctx context.Context, _ int) error {
		resp, err := c.postCibaForm(ctx, operation, target, form)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			mapped := oauth2ErrorAnyStatus(resp, operation)
			var protocolErr *OAuthProtocolError
			if errors.As(mapped, &protocolErr) || !statusIsRetryable(resp.StatusCode) {
				decisive = mapped
				return errStopRetry
			}
			return mapped
		}
		// §33.7 rule 7: a 200 is consumed before anything else, and a body
		// that does not parse is not retried — the server may already have
		// redeemed the request.
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			decisive = &NetworkError{Message: operation + ": could not decode the token response"}
			return errStopRetry
		}
		return nil
	})
	if decisive != nil {
		return OidcTokenSet{}, false, decisive
	}
	if retryErr != nil {
		_, transient := retryErr.(*NetworkError)
		return OidcTokenSet{}, transient, retryErr
	}
	set, err := c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.session.oidc.clientID,
		clockSkewSec: c.session.oidc.clockSkewSec,
	})
	return set, false, err
}

// CibaAwait polls for initiated's outcome until it is decided or expires
// (§33.1, §33.7). It surfaces nothing to the user — AXIAM notified them.
//
//   - The first poll waits one interval (the response's, or 5 s): polling
//     earlier only earns slow_down and a longer wait.
//   - slow_down adds 5 s to the interval, cumulatively and permanently;
//     authorization_pending never lowers it.
//   - A transport failure, 5xx, 408 or 429 that outlived §16 inside the poll,
//     and a rate_limit_exceeded answer, are not terminal: the loop waits the
//     interval and polls again.
//   - Polling stops at ReceivedAt + ExpiresIn even if the server has not said
//     expired_token; the same expired_token *OAuthProtocolError is then raised
//     locally, with no request.
//   - access_denied, expired_token, invalid_grant and every other answer end
//     the loop.
//
// The token set is returned, and adopted only with AdoptAsCredential. In
// PING mode, do not call this: call CibaPoll once from the ping handler (after
// answering the ping), and fall back to this loop only once half of ExpiresIn
// has passed without a ping (§33.7 rule 6).
func (c *Client) CibaAwait(ctx context.Context, initiated CibaInitiateResponse, params CibaAwaitParams) (OidcTokenSet, error) {
	clock := params.Clock
	if clock == nil {
		clock = systemCibaClock{}
	}
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}
	deadline := initiated.ReceivedAt.Add(time.Duration(initiated.ExpiresIn) * time.Second)
	interval := time.Duration(initiated.Interval) * time.Second
	if interval <= 0 {
		interval = DefaultCibaInterval
	}
	for {
		if !clock.Now().Add(interval).Before(deadline) {
			return OidcTokenSet{}, &OAuthProtocolError{
				AuthError:        AuthError{Message: "expired_token: the CIBA request expired before it was decided (client-side deadline from expires_in; CONTRACT.md §33.7 rule 4)"},
				ErrorCode:        "expired_token",
				ErrorDescription: "the CIBA request expired before it was decided",
			}
		}
		if err := clock.Sleep(ctx, interval); err != nil {
			return OidcTokenSet{}, err
		}
		set, transient, err := c.cibaPoll(ctx, CibaPollParams{
			AuthReqID:     initiated.AuthReqID,
			TenantID:      params.TenantID,
			Configuration: &configuration,
		})
		if err == nil {
			if params.AdoptAsCredential {
				c.resetScopeUnknown()
				c.replaceDeviceCredential()
				c.adoptOidcCredential(set.AccessToken)
			}
			return set, nil
		}
		var protocolErr *OAuthProtocolError
		switch {
		case errors.As(err, &protocolErr) && protocolErr.ErrorCode == "slow_down":
			interval += CibaSlowDownIncrement // §33.7 rule 3: never reset.
		case errors.As(err, &protocolErr) && (protocolErr.ErrorCode == "authorization_pending" ||
			protocolErr.ErrorCode == "rate_limit_exceeded"):
			// Keep polling at the current interval; a 429 counts as one interval.
		case transient:
			// §33.7 rule 5: an approved request must survive a server restart.
		default:
			return OidcTokenSet{}, err
		}
	}
}

// CibaHandlePing checks a ping AXIAM delivered to your notification endpoint and
// returns the auth_req_id it names (CIBA Core §10.2, CONTRACT.md §33.1). NO
// I/O: it neither answers the HTTP request nor calls the token endpoint.
//
// headers are the request's headers (r.Header), body its raw body, and
// expectedToken the ClientNotificationToken you sent with the request.
//
//  1. Exactly one Authorization header, scheme Bearer (any case), one space,
//     and the token — compared in constant time. Otherwise an *AuthError whose
//     message names no value.
//  2. A JSON object with a non-empty string auth_req_id; any other member is
//     ignored. Otherwise a local *ValidationError.
//
// Answer 204 as soon as this returns, THEN call CibaPoll — AXIAM retries a
// ping that is not answered quickly. It does not check that the auth_req_id is
// one you issued: the token endpoint answers invalid_grant for any other.
func (c *Client) CibaHandlePing(headers http.Header, body []byte, expectedToken Sensitive) (Sensitive, error) {
	refused := &AuthError{Message: "ciba ping refused: the Authorization header is not the expected bearer (CONTRACT.md §33.1)"}
	var values []string
	for name, v := range headers {
		if strings.EqualFold(name, "Authorization") {
			values = append(values, v...)
		}
	}
	if len(values) != 1 {
		return "", refused
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", refused
	}
	expected := expectedToken.expose()
	if expected == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return "", refused
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil || members == nil {
		return "", localRefusal("ciba_handle_ping", "body", "the ping body is not a JSON object")
	}
	id, ok := rawString(members["auth_req_id"])
	if !ok || id == "" {
		return "", localRefusal("ciba_handle_ping", "auth_req_id", "the ping body carries no non-empty auth_req_id string")
	}
	return Sensitive(id), nil
}
