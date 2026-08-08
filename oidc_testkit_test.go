package axiam

// Shared OIDC test fixtures: a real Ed25519 key + JWKS server, ID-token
// signing, and an OidcConfiguration builder — mirroring the signing helpers
// already established in login_test.go and internal/jwks/verifier_test.go
// (D-10: deterministic, no live network).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// generateOidcTestKey creates a fresh Ed25519 key pair and its corresponding
// public jwk.Key tagged with kid + alg.
func generateOidcTestKey(t *testing.T, kid string) (ed25519.PrivateKey, jwk.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pubJWK, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return priv, pubJWK
}

func marshalOidcJWKS(t *testing.T, keys ...jwk.Key) []byte {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		if err := set.AddKey(k); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// signIDTokenEdDSA signs an arbitrary claim map as a compact JWS with kid,
// producing a syntactically valid ID token for oidcExchange/oidcRefresh
// tests.
func signIDTokenEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal id_token claims: %v", err)
	}
	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import priv: %v", err)
	}
	if err := pk.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// signIDTokenHS256 builds a well-formed, but wrong-algorithm, ID token, to
// prove the alg allowlist rejects it (§12.4 rule 1, incl. non-EdDSA algs).
func signIDTokenHS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal id_token claims: %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), []byte("irrelevant-secret")))
	if err != nil {
		t.Fatalf("jws.Sign HS256: %v", err)
	}
	return string(signed)
}

// signIDTokenNone builds an `{"alg":"none"}` unsecured JWS (RFC 7515 §5.2),
// to prove §12.4 rule 1 rejects "none" like any other non-EdDSA algorithm.
func signIDTokenNone(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal id_token claims: %v", err)
	}
	header := `{"alg":"none"}`
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(payload) + "."
}

// discoveryDoc builds a syntactically-complete OidcConfiguration pointed at
// base's endpoints, ready to marshal as the discovery-document response
// body.
func discoveryDoc(base string) OidcConfiguration {
	return OidcConfiguration{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/oauth2/authorize",
		TokenEndpoint:                     base + "/oauth2/token",
		UserinfoEndpoint:                  base + "/oauth2/userinfo",
		JwksURI:                           base + "/oauth2/jwks",
		RevocationEndpoint:                base + "/oauth2/revoke",
		IntrospectionEndpoint:             base + "/oauth2/introspect",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"EdDSA"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "nonce"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		DeviceAuthorizationEndpoint:       base + "/oauth2/device_authorization",
		EndSessionEndpoint:                base + "/oauth2/end_session",
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,
	}
}

// discoveryDocWithoutOptionalEndpoints is discoveryDoc with the §14/§12.7
// endpoints deliberately absent — the shape an older AXIAM, or a third-party
// OP without those features, publishes. Used to assert the SDK errors rather
// than concatenating a URL onto the issuer (§12.7.2 rule 1).
func discoveryDocWithoutOptionalEndpoints(base string) OidcConfiguration {
	doc := discoveryDoc(base)
	doc.DeviceAuthorizationEndpoint = ""
	doc.EndSessionEndpoint = ""
	return doc
}

// oidcTestServer is a minimal, per-test-configurable fake AXIAM OIDC
// provider: discovery + JWKS are always served; the remaining endpoints
// delegate to caller-supplied handler funcs (nil = 404), so each test wires
// up only what it needs while sharing one Ed25519 signing key.
type oidcTestServer struct {
	*httptest.Server
	Priv ed25519.PrivateKey
	Pub  jwk.Key
	Kid  string

	// DiscoveryDoc, when set, replaces the served discovery document — used
	// to serve one WITHOUT the §14/§12.7 endpoints.
	DiscoveryDoc func(base string) OidcConfiguration

	TokenHandler       http.HandlerFunc
	DeviceAuthHandler  http.HandlerFunc
	IntrospectHandler  http.HandlerFunc
	RevokeHandler      http.HandlerFunc
	SsoStartHandler    http.HandlerFunc
	SsoCompleteHandler http.HandlerFunc

	tokenCalls      int32
	deviceAuthCalls int32
	introspectCalls int32
	revokeCalls     int32
}

func newOidcTestServer(t *testing.T) *oidcTestServer {
	t.Helper()
	priv, pub := generateOidcTestKey(t, "test-kid-1")
	s := &oidcTestServer{Priv: priv, Pub: pub, Kid: "test-kid-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := discoveryDoc(s.Server.URL)
		if s.DiscoveryDoc != nil {
			doc = s.DiscoveryDoc(s.Server.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(marshalOidcJWKS(t, s.Pub))
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.tokenCalls, 1)
		if s.TokenHandler != nil {
			s.TokenHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.HandleFunc("/oauth2/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.deviceAuthCalls, 1)
		if s.DeviceAuthHandler != nil {
			s.DeviceAuthHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.introspectCalls, 1)
		if s.IntrospectHandler != nil {
			s.IntrospectHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.revokeCalls, 1)
		if s.RevokeHandler != nil {
			s.RevokeHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.HandleFunc("/api/v1/auth/federation/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		if s.SsoStartHandler != nil {
			s.SsoStartHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.HandleFunc("/api/v1/auth/federation/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if s.SsoCompleteHandler != nil {
			s.SsoCompleteHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

func (s *oidcTestServer) TokenCalls() int32 {
	return atomic.LoadInt32(&s.tokenCalls)
}

func (s *oidcTestServer) DeviceAuthCalls() int32 {
	return atomic.LoadInt32(&s.deviceAuthCalls)
}

func (s *oidcTestServer) IntrospectCalls() int32 {
	return atomic.LoadInt32(&s.introspectCalls)
}

func (s *oidcTestServer) RevokeCalls() int32 {
	return atomic.LoadInt32(&s.revokeCalls)
}

// validIDTokenClaims returns a fresh, currently-valid ID-token claim set for
// srv/clientID/nonce, ready for signIDTokenEdDSA. Callers mutate the
// returned map to build a specific failure scenario.
func validIDTokenClaims(srv *httptest.Server, clientID, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   srv.URL,
		"sub":   "user-123",
		"aud":   clientID,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}
}
