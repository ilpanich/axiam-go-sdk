package axiam

// The SSF receiver helper — CONTRACT.md §32.8's eight helper tests, plus
// discovery, the replay store and the poll's edge cases.
//
// Every key is an Ed25519 key generated here from fresh randomness, and every
// SET is signed here: no key literal, no captured token.

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	ssfIssuer   = "https://iam.example.test/t/22222222-2222-4222-8222-222222222222"
	ssfAudience = "https://rp.example.test"
)

type setKey struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSetKey(t *testing.T) setKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return setKey{kid: "k-" + uuid.NewString(), priv: priv, pub: pub}
}

func (k setKey) jwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
		"kid": k.kid, "x": base64.RawURLEncoding.EncodeToString(k.pub)}
}

func b64JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (k setKey) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	input := b64JSON(t, header) + "." + b64JSON(t, claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(input)))
}

func (k setKey) signSet(t *testing.T, claims map[string]any) string {
	t.Helper()
	return k.sign(t, map[string]any{"alg": "EdDSA", "typ": "secevent+jwt", "kid": k.kid}, claims)
}

func setClaims() map[string]any {
	return map[string]any{
		"iss": ssfIssuer, "aud": ssfAudience, "iat": 1791500000,
		"jti": uuid.NewString(), "txn": "t-1",
		"sub_id": map[string]any{"format": "iss_sub", "iss": ssfIssuer, "sub": uuid.NewString()},
		"events": map[string]any{string(SsfEventTypeSessionRevoked): map[string]any{"event_timestamp": 1791500000}},
	}
}

func with(claims map[string]any, k string, v any) map[string]any {
	claims[k] = v
	return claims
}

func without(claims map[string]any, k string) map[string]any {
	delete(claims, k)
	return claims
}

// ssfServer serves a JWKS (counting fetches) and lets a test mount more.
type ssfServer struct {
	*httptest.Server
	mux        *http.ServeMux
	jwksHits   atomic.Int32
	mu         sync.Mutex
	jwksStatus int
	keys       []map[string]any
}

func newSsfServer(t *testing.T, keys ...setKey) *ssfServer {
	t.Helper()
	s := &ssfServer{mux: http.NewServeMux(), jwksStatus: 200}
	for _, k := range keys {
		s.keys = append(s.keys, k.jwk())
	}
	s.mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, _ *http.Request) {
		s.jwksHits.Add(1)
		s.mu.Lock()
		status, keys := s.jwksStatus, s.keys
		s.mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	s.Server = httptest.NewServer(s.mux)
	t.Cleanup(s.Close)
	return s
}

func ssfClient(t *testing.T, base string, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(base, "acme", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newReceiver(t *testing.T, s *ssfServer, opts ...Option) (*SsfReceiver, string) {
	t.Helper()
	token := randomSecret(t, "cc-")
	r, err := NewSsfReceiver(ssfClient(t, s.URL, opts...), SsfReceiverConfig{
		Issuer: ssfIssuer, Audience: ssfAudience, JWKSURI: s.URL + "/oauth2/jwks",
		AccessTokenProvider: func(context.Context) (Sensitive, error) { return Sensitive(token), nil },
	})
	if err != nil {
		t.Fatalf("NewSsfReceiver: %v", err)
	}
	return r, token
}

func refusalReason(t *testing.T, r *SsfReceiver, set string) SetFailureReason {
	t.Helper()
	_, err := r.VerifySet(context.Background(), set)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want an AuthError refusal, got %T", err)
	}
	reason, ok := SetFailureReasonOf(err)
	if !ok {
		t.Fatal("the refusal carries no SET reason")
	}
	return reason
}

// ── 1 ──

func TestSsfReceiver_ASetSignedByTheJWKSKeyVerifiesIntoItsClaims(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	claims := setClaims()
	event, err := r.VerifySet(context.Background(), key.signSet(t, claims))
	if err != nil {
		t.Fatalf("verifies: %v", err)
	}
	if event.Jti != claims["jti"] || event.Iat != 1791500000 || event.Iss != ssfIssuer ||
		string(event.Aud) != `"`+ssfAudience+`"` || event.Txn != "t-1" ||
		event.EventType != SsfEventTypeSessionRevoked {
		t.Fatalf("every field is the claim's: %+v", event)
	}
	var gotEvent, gotSub map[string]any
	_ = json.Unmarshal(event.Event, &gotEvent)
	_ = json.Unmarshal(event.SubID, &gotSub)
	if gotEvent["event_timestamp"] != float64(1791500000) || gotSub["sub"] != claims["sub_id"].(map[string]any)["sub"] {
		t.Fatal("event and sub_id are the claim's objects")
	}

	// An aud array containing the audience, and the media-type spelling of typ.
	arr := with(setClaims(), "aud", []string{"other", ssfAudience})
	set := key.sign(t, map[string]any{"alg": "EdDSA", "typ": "Application/SecEvent+JWT", "kid": key.kid}, arr)
	event, err = r.VerifySet(context.Background(), set)
	if err != nil || string(event.Aud) != `["other","`+ssfAudience+`"]` {
		t.Fatalf("array aud: %v", err)
	}
}

// ── 2 ──

func TestSsfReceiver_AWrongTypOrAlgIsRefusedInThatOrder(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	claims := setClaims()
	for _, header := range []map[string]any{
		{"alg": "EdDSA", "kid": key.kid},
		{"alg": "EdDSA", "typ": "JWT", "kid": key.kid},
		{"alg": "none", "kid": key.kid},
	} {
		if got := refusalReason(t, r, key.sign(t, header, claims)); got != SetFailureInvalidType {
			t.Fatalf("typ: got %s", got)
		}
	}
	none := b64JSON(t, map[string]any{"alg": "none", "typ": "secevent+jwt"}) + "." + b64JSON(t, claims) + "."
	if got := refusalReason(t, r, none); got != SetFailureInvalidKey {
		t.Fatalf("alg none: got %s", got)
	}
	hsInput := b64JSON(t, map[string]any{"alg": "HS256", "typ": "secevent+jwt", "kid": key.kid}) + "." + b64JSON(t, claims)
	mac := hmac.New(sha256.New, []byte(uuid.NewString()))
	mac.Write([]byte(hsInput))
	hs := hsInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if got := refusalReason(t, r, hs); got != SetFailureInvalidKey {
		t.Fatalf("alg HS256: got %s", got)
	}
	for _, malformed := range []string{"a.b", "!!.@@.##", "e30.e30.!!", b64JSON(t, []int{1}) + "." + b64JSON(t, claims) + "."} {
		if got := refusalReason(t, r, malformed); got != SetFailureMalformed {
			t.Fatalf("malformed: got %s", got)
		}
	}
	if got := refusalReason(t, r, key.sign(t, map[string]any{"alg": "EdDSA", "typ": "secevent+jwt"}, claims)); got != SetFailureInvalidKey {
		t.Fatalf("no kid: got %s", got)
	}
}

// ── 3 ──

func TestSsfReceiver_AnotherKeyOrATamperedPayloadIsInvalidKey(t *testing.T) {
	key := newSetKey(t)
	rogue := newSetKey(t)
	rogue.kid = key.kid
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	if got := refusalReason(t, r, rogue.signSet(t, setClaims())); got != SetFailureInvalidKey {
		t.Fatalf("another key: got %s", got)
	}
	parts := strings.Split(key.signSet(t, setClaims()), ".")
	parts[1] = b64JSON(t, with(setClaims(), "txn", "x"))
	if got := refusalReason(t, r, strings.Join(parts, ".")); got != SetFailureInvalidKey {
		t.Fatalf("tampered: got %s", got)
	}
}

// ── 4 ──

func TestSsfReceiver_AnotherIssuerOrAudienceIsRefused(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	if got := refusalReason(t, r, key.signSet(t, with(setClaims(), "iss", "https://iam.example.test"))); got != SetFailureInvalidIssuer {
		t.Fatalf("iss: got %s", got)
	}
	for _, aud := range []any{[]string{"https://elsewhere.test"}, "https://elsewhere.test", 42, nil} {
		if got := refusalReason(t, r, key.signSet(t, with(setClaims(), "aud", aud))); got != SetFailureInvalidAudience {
			t.Fatalf("aud: got %s", got)
		}
	}
}

// ── 5 ──

func TestSsfReceiver_ExpSubTwoEventsOrNoJtiIsInvalidRequest(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	two := with(setClaims(), "events", map[string]any{
		string(SsfEventTypeAccountDisabled): map[string]any{}, string(SsfEventTypeAccountPurged): map[string]any{}})
	for i, claims := range []map[string]any{
		with(setClaims(), "exp", 1891500000),
		with(setClaims(), "sub", "u"),
		two,
		without(setClaims(), "jti"),
		with(setClaims(), "jti", ""),
		without(setClaims(), "iat"),
		with(setClaims(), "iat", "yesterday"),
		without(setClaims(), "sub_id"),
		with(setClaims(), "sub_id", "u"),
		without(setClaims(), "events"),
		with(setClaims(), "events", map[string]any{}),
	} {
		if got := refusalReason(t, r, key.signSet(t, claims)); got != SetFailureInvalidRequest {
			t.Fatalf("case %d: got %s", i, got)
		}
	}
}

// ── 6 ──

func TestSsfReceiver_AReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	set := key.signSet(t, setClaims())
	if _, err := r.VerifySet(context.Background(), set); err != nil {
		t.Fatalf("first time: %v", err)
	}
	if got := refusalReason(t, r, set); got != SetFailureReplayed {
		t.Fatalf("second time: got %s", got)
	}

	c := ssfClient(t, s.URL)
	_, err := NewSsfReceiver(c, SsfReceiverConfig{Issuer: ssfIssuer, Audience: ssfAudience,
		JWKSURI: s.URL + "/oauth2/jwks", ReplayWindow: 6 * 24 * time.Hour})
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("a window below seven days: want ValidationError, got %T", err)
	}
	longer, err := NewSsfReceiver(c, SsfReceiverConfig{Issuer: ssfIssuer, Audience: ssfAudience,
		JWKSURI: s.URL + "/oauth2/jwks", ReplayWindow: 30 * 24 * time.Hour})
	if err != nil || longer.window != 30*24*time.Hour {
		t.Fatalf("a longer window is accepted: %v", err)
	}
}

// ── 7 ──

func TestSsfReceiver_AnUnknownKidCostsOneRefetchAndASecondOneNone(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	r, _ := newReceiver(t, s)
	if _, err := r.VerifySet(context.Background(), key.signSet(t, setClaims())); err != nil {
		t.Fatalf("primes the cache: %v", err)
	}
	if s.jwksHits.Load() != 1 {
		t.Fatalf("one fetch, got %d", s.jwksHits.Load())
	}
	if got := refusalReason(t, r, newSetKey(t).signSet(t, setClaims())); got != SetFailureInvalidKey {
		t.Fatalf("stranger: got %s", got)
	}
	if s.jwksHits.Load() != 2 {
		t.Fatalf("exactly one refetch, got %d", s.jwksHits.Load())
	}
	if got := refusalReason(t, r, newSetKey(t).signSet(t, setClaims())); got != SetFailureInvalidKey {
		t.Fatalf("another: got %s", got)
	}
	if s.jwksHits.Load() != 2 {
		t.Fatalf("no refetch within the minute, got %d", s.jwksHits.Load())
	}

	// A minute later, an unknown kid may refetch again — and a rotated-in key
	// is then found.
	rotated := newSetKey(t)
	s.mu.Lock()
	s.keys = append(s.keys, rotated.jwk())
	s.mu.Unlock()
	r.mu.Lock()
	r.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	r.mu.Unlock()
	if _, err := r.VerifySet(context.Background(), rotated.signSet(t, setClaims())); err != nil {
		t.Fatalf("a rotated key is found after the cooldown: %v", err)
	}
	if s.jwksHits.Load() != 3 {
		t.Fatalf("one more fetch, got %d", s.jwksHits.Load())
	}
}

// ── 8 ──

func TestSsfReceiver_PollPassesAckAndSetErrsThroughAndSortsTheAnswer(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	stream := uuid.NewString()
	good := setClaims()
	bad := with(setClaims(), "iss", "https://impostor.test")
	goodJti, badJti := good["jti"].(string), bad["jti"].(string)
	reply := map[string]any{
		"sets":          map[string]any{goodJti: key.signSet(t, good), badJti: key.signSet(t, bad)},
		"moreAvailable": true,
	}
	type seen struct {
		body string
		auth string
		hdr  http.Header
	}
	var mu sync.Mutex
	var requests []seen
	s.mux.HandleFunc("/ssf/v1/poll/"+stream, func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		requests = append(requests, seen{string(readAllBody(req)), req.Header.Get("Authorization"), req.Header.Clone()})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	})
	r, token := newReceiver(t, s)
	result, err := r.Poll(context.Background(), stream, SsfPollOptions{
		MaxEvents:         ptr(10),
		ReturnImmediately: ptr(true),
		Ack:               []string{"done-1", "done-2"},
		SetErrs:           map[string]SetErr{"old-1": NewSetErr(SetFailureReplayed)},
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !result.MoreAvailable || len(result.Events) != 1 || result.Events[0].Jti != goodJti {
		t.Fatalf("verified apart: %+v", result.Events)
	}
	if len(result.Refused) != 1 || result.Refused[0].Jti != badJti || result.Refused[0].Reason != SetFailureInvalidIssuer {
		t.Fatalf("refused apart: %+v", result.Refused)
	}
	if len(requests) != 1 {
		t.Fatalf("one request, got %d", len(requests))
	}
	var sent, want any
	_ = json.Unmarshal([]byte(requests[0].body), &sent)
	_ = json.Unmarshal([]byte(`{"maxEvents":10,"returnImmediately":true,"ack":["done-1","done-2"],"setErrs":{"old-1":{"err":"invalid_request"}}}`), &want)
	if !reflect.DeepEqual(sent, want) {
		t.Fatal("ack and setErrs must be sent exactly as given, and nothing acknowledged on the caller's behalf")
	}
	if requests[0].auth != "Bearer "+token {
		t.Fatal("the provider's token is the bearer")
	}
	if requests[0].hdr.Get("Cookie") != "" || requests[0].hdr.Get("X-CSRF-Token") != "" {
		t.Fatal("no SDK session rides along")
	}

	// A second poll with no options sends an empty object: still no ack.
	if _, err := r.Poll(context.Background(), stream, SsfPollOptions{}); err != nil {
		t.Fatalf("again: %v", err)
	}
	if requests[1].body != `{}` {
		t.Fatal("a poll with no options sends {}")
	}
}

// §32.8 helper test 8, contract 1.59 (§34.2 P1): a batch of two whose second
// SET names an unknown kid while the refetch fails. Afterwards the first SET's
// jti is not in the store, or the first SET was returned in events — never
// recorded and lost.
func TestSsfReceiver_PollNeverKeepsAJtiItDoesNotReturn(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	stream := uuid.NewString()
	first := with(setClaims(), "jti", "a-"+uuid.NewString())
	second := with(setClaims(), "jti", "b-"+uuid.NewString())
	firstJti, secondJti := first["jti"].(string), second["jti"].(string)
	stranger := newSetKey(t)
	batch := map[string]any{"sets": map[string]any{
		firstJti:  key.signSet(t, first),
		secondJti: stranger.signSet(t, second),
	}}
	s.mux.HandleFunc("/ssf/v1/poll/"+stream, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(batch)
	})
	r, _ := newReceiver(t, s, WithRetryDisabled())
	// Prime the cache, so the first SET of the batch verifies from it and only
	// the second one's unknown kid triggers the refetch — which then fails.
	if _, err := r.VerifySet(context.Background(), key.signSet(t, setClaims())); err != nil {
		t.Fatalf("primes the cache: %v", err)
	}
	s.mu.Lock()
	s.jwksStatus = 503
	s.mu.Unlock()

	result, err := r.Poll(context.Background(), stream, SsfPollOptions{})
	returned := false
	for _, event := range result.Events {
		returned = returned || event.Jti == firstJti
	}
	if err == nil && !returned {
		t.Fatalf("the first SET verified, so it is returned: %+v", result)
	}
	if err != nil {
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("a failed refetch is a NetworkError, not a verdict: %T", err)
		}
		if _, refused := SetFailureReasonOf(err); refused {
			t.Fatal("a failed refetch carries no reason code")
		}
	}
	if s.jwksHits.Load() != 2 {
		t.Fatalf("one refetch for the unknown kid, got %d fetches", s.jwksHits.Load())
	}

	// The transmitter re-offers what was not acknowledged. If the first SET
	// was not returned, its jti was not recorded either: re-offered, it
	// verifies — it does not read as replayed.
	if !returned {
		s.mu.Lock()
		s.jwksStatus = 200
		s.mu.Unlock()
		again, err := r.Poll(context.Background(), stream, SsfPollOptions{})
		if err != nil {
			t.Fatalf("re-poll: %v", err)
		}
		if len(again.Events) != 1 || again.Events[0].Jti != firstJti {
			t.Fatalf("the first SET's jti was recorded but not returned, so the event is lost: events %+v, refused %+v",
				again.Events, again.Refused)
		}
		if len(again.Refused) != 1 || again.Refused[0].Jti != secondJti || again.Refused[0].Reason != SetFailureInvalidKey {
			t.Fatalf("the stranger's SET is refused invalid_key: %+v", again.Refused)
		}
		// Returned, it is now recorded: offered once more, it reads replayed.
		third, err := r.Poll(context.Background(), stream, SsfPollOptions{})
		if err != nil {
			t.Fatalf("third poll: %v", err)
		}
		if len(third.Events) != 0 || len(third.Refused) != 2 ||
			third.Refused[0].Jti != firstJti || third.Refused[0].Reason != SetFailureReplayed {
			t.Fatalf("a returned SET offered again is replayed: events %+v, refused %+v", third.Events, third.Refused)
		}
	}
}

func TestSsfReceiver_PollIsNotRetriedOn400ButIsOn503(t *testing.T) {
	s := newSsfServer(t)
	var hits atomic.Int32
	var status atomic.Int32
	status.Store(400)
	s.mux.HandleFunc("/ssf/v1/poll/s-1", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(`{"error":"push stream","message":"push stream"}`))
	})
	// Retry ENABLED (the default), with the jitter pinned so the test is fast.
	r, _ := newReceiver(t, s, withJitterSource(func() float64 { return 0 }))
	_, err := r.Poll(context.Background(), "s-1", SsfPollOptions{})
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("400: want ValidationError, got %T", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("a 400 is not retried: %d requests", hits.Load())
	}
	status.Store(503)
	hits.Store(0)
	_, err = r.Poll(context.Background(), "s-1", SsfPollOptions{})
	var netErr *NetworkError
	if !errors.As(err, &netErr) || hits.Load() != MaxAttempts {
		t.Fatalf("a 503 follows §16: %T after %d requests", err, hits.Load())
	}
}

// ── Discovery, configuration and edges ─────────────────────────────────────

func TestSsfReceiver_DiscoverySuppliesTheJWKSURIAndMustNameTheIssuer(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	s.mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": ssfIssuer, "jwks_uri": s.URL + "/oauth2/jwks"})
	})
	c := ssfClient(t, s.URL)
	r, err := NewSsfReceiver(c, SsfReceiverConfig{Issuer: ssfIssuer, Audience: ssfAudience,
		DiscoveryURL: s.URL + "/.well-known/ssf-configuration"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.VerifySet(context.Background(), key.signSet(t, setClaims())); err != nil {
		t.Fatalf("via discovery: %v", err)
	}

	wrong, err := NewSsfReceiver(c, SsfReceiverConfig{Issuer: "https://someone-else.test", Audience: ssfAudience,
		DiscoveryURL: s.URL + "/.well-known/ssf-configuration"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrong.VerifySet(context.Background(), key.signSet(t, setClaims()))
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("an issuer mismatch is a NetworkError, got %T", err)
	}
	if _, refused := SetFailureReasonOf(err); refused {
		t.Fatal("and not a verdict on the SET")
	}
	// A poll with no token provider is refused locally.
	var authErr *AuthError
	if _, err := wrong.Poll(context.Background(), "s", SsfPollOptions{}); !errors.As(err, &authErr) {
		t.Fatalf("no provider: want AuthError, got %T", err)
	}
	if !strings.Contains(wrong.String(), "SsfReceiver") {
		t.Fatal("String renders the configuration")
	}
}

func TestSsfReceiver_AJWKSFailureIsANetworkErrorAndAbortsThePoll(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	s.jwksStatus = 500
	s.mux.HandleFunc("/ssf/v1/poll/s-2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": map[string]any{"j": key.signSet(t, setClaims())}})
	})
	r, _ := newReceiver(t, s, WithRetryDisabled())
	_, err := r.VerifySet(context.Background(), key.signSet(t, setClaims()))
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError, got %T", err)
	}
	if _, err := r.Poll(context.Background(), "s-2", SsfPollOptions{}); !errors.As(err, &netErr) {
		t.Fatalf("the poll aborts with the JWKS error, got %T", err)
	}
}

func TestSsfReceiver_APolledSetUnderAnotherKeyOrNotAStringIsRefused(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)
	claims := setClaims()
	s.mux.HandleFunc("/ssf/v1/poll/s-3", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": map[string]any{
			"not-its-jti": key.signSet(t, claims), "number": 42}})
	})
	r, _ := newReceiver(t, s)
	result, err := r.Poll(context.Background(), "s-3", SsfPollOptions{})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	got := map[string]SetFailureReason{}
	for _, refused := range result.Refused {
		got[refused.Jti] = refused.Reason
	}
	if got["not-its-jti"] != SetFailureInvalidRequest || got["number"] != SetFailureMalformed || len(result.Events) != 0 {
		t.Fatalf("refusals: %v", got)
	}
}

func TestSsfReceiver_ANonEd25519KeyAndAnUnreadablePollAnswer(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t)
	s.keys = []map[string]any{{"kty": "RSA", "kid": key.kid, "n": "AQAB", "e": "AQAB"}, {"kty": "OKP"}}
	s.mux.HandleFunc("/ssf/v1/poll/s-4", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	r, _ := newReceiver(t, s)
	if got := refusalReason(t, r, key.signSet(t, setClaims())); got != SetFailureInvalidKey {
		t.Fatalf("an RSA key under the kid: got %s", got)
	}
	var netErr *NetworkError
	if _, err := r.Poll(context.Background(), "s-4", SsfPollOptions{}); !errors.As(err, &netErr) {
		t.Fatalf("an unreadable answer is a NetworkError, got %T", err)
	}
}

func TestSsfReceiver_ConfigurationIsCheckedAtConstruction(t *testing.T) {
	c := ssfClient(t, "https://iam.example.test")
	var verr *ValidationError
	for i, cfg := range []SsfReceiverConfig{
		{Audience: ssfAudience, JWKSURI: "https://iam.example.test/oauth2/jwks"},
		{Issuer: ssfIssuer, JWKSURI: "https://iam.example.test/oauth2/jwks"},
		{Issuer: ssfIssuer, Audience: ssfAudience},
		{Issuer: ssfIssuer, Audience: ssfAudience, JWKSURI: "https://a/j", DiscoveryURL: "https://a/d"},
		{Issuer: ssfIssuer, Audience: ssfAudience, JWKSURI: "http://iam.example.test/oauth2/jwks"},
		{Issuer: ssfIssuer, Audience: ssfAudience, DiscoveryURL: "/relative"},
		{Issuer: ssfIssuer, Audience: ssfAudience, JWKSURI: "ftp://iam.example.test/jwks"},
	} {
		if _, err := NewSsfReceiver(c, cfg); !errors.As(err, &verr) {
			t.Fatalf("case %d: want ValidationError, got %T", i, err)
		}
	}
	if _, err := NewSsfReceiver(nil, SsfReceiverConfig{}); !errors.As(err, &verr) {
		t.Fatal("a nil client is refused")
	}
	_ = c.Close()
	r, err := NewSsfReceiver(c, SsfReceiverConfig{Issuer: ssfIssuer, Audience: ssfAudience,
		JWKSURI: "https://iam.example.test/oauth2/jwks"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Poll(context.Background(), "s", SsfPollOptions{}); err == nil {
		t.Fatal("a closed client refuses to poll")
	}
}

func TestSsfReceiver_PushErrorCodesAreRFC8935Codes(t *testing.T) {
	for reason, code := range map[SetFailureReason]string{
		SetFailureMalformed:       "invalid_request",
		SetFailureInvalidType:     "invalid_request",
		SetFailureReplayed:        "invalid_request",
		SetFailureInvalidKey:      "invalid_key",
		SetFailureInvalidIssuer:   "invalid_issuer",
		SetFailureInvalidAudience: "invalid_audience",
		SetFailureInvalidRequest:  "invalid_request",
	} {
		if reason.PushErrorCode() != code || NewSetErr(reason).Err != code {
			t.Fatalf("%s: want %s", reason, code)
		}
	}
	// A §12.4 AuthError spelled like a SET reason is not mistaken for one.
	if _, ok := SetFailureReasonOf(&AuthError{Message: "x", Reason: "invalid_issuer"}); ok {
		t.Fatal("only a SET refusal carries a SetFailureReason")
	}
}

func TestSsfReceiver_TheMemoryStoreForgetsAfterTheWindow(t *testing.T) {
	var store MemorySsfReplayStore
	fresh := func(s *MemorySsfReplayStore, jti string, window time.Duration) bool {
		t.Helper()
		ok, err := s.CheckAndRecord(jti, window)
		if err != nil {
			t.Fatalf("the in-memory store always answers: %v", err)
		}
		return ok
	}
	if !fresh(&store, "a", time.Minute) || fresh(&store, "a", time.Minute) {
		t.Fatal("a second sighting is refused")
	}
	first := fresh(&store, "b", 0)
	again := fresh(&store, "b", 0)
	if !first || !again {
		t.Fatal("an expired entry is new again")
	}
	now := time.Now()
	clocked := MemorySsfReplayStore{now: func() time.Time { return now }}
	fresh(&clocked, "c", time.Hour)
	now = now.Add(2 * time.Hour)
	if !fresh(&clocked, "c", time.Hour) {
		t.Fatal("forgotten after the window")
	}
}

// ── §32.7 step 9, contract 1.60 §34.2 P4: a store that cannot answer gives no verdict ──

// flakyReplayStore is a store whose backend cannot answer for the jtis in
// broken (it returns an error and records nothing) and answers from memory for
// every other. calls counts every question.
type flakyReplayStore struct {
	mu     sync.Mutex
	broken map[string]bool
	seen   map[string]bool
	calls  atomic.Int32
}

var errStoreDown = errors.New("shared cache unreachable")

func (s *flakyReplayStore) CheckAndRecord(jti string, _ time.Duration) (bool, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken[jti] {
		return false, errStoreDown
	}
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.seen[jti] {
		return false, nil
	}
	s.seen[jti] = true
	return true, nil
}

func (s *flakyReplayStore) holds(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[jti]
}

func (s *flakyReplayStore) heal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broken = nil
}

func storeReceiver(t *testing.T, s *ssfServer, store SsfReplayStore) *SsfReceiver {
	t.Helper()
	r, err := NewSsfReceiver(ssfClient(t, s.URL), SsfReceiverConfig{
		Issuer: ssfIssuer, Audience: ssfAudience, JWKSURI: s.URL + "/oauth2/jwks", ReplayStore: store,
		AccessTokenProvider: func(context.Context) (Sensitive, error) { return Sensitive(randomSecret(t, "cc-")), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// §32.8 helper test 6, the store-failure case (contract 1.60, B1/P4).
func TestSsfReceiver_Test6_AStoreThatCannotAnswerGivesNoVerdict(t *testing.T) {
	key := newSetKey(t)
	s := newSsfServer(t, key)

	down := with(setClaims(), "jti", "z-"+uuid.NewString())
	downJti := down["jti"].(string)
	downSet := key.signSet(t, down)
	store := &flakyReplayStore{broken: map[string]bool{downJti: true}}
	r := storeReceiver(t, s, store)

	// VerifySet: the §2 NetworkError, no reason code, never replayed; the
	// store's own error is reachable.
	_, err := r.VerifySet(context.Background(), downSet)
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("a store that cannot answer is a NetworkError, got %T: %v", err, err)
	}
	if reason, refused := SetFailureReasonOf(err); refused {
		t.Fatalf("no reason code, and in particular never replayed: %s", reason)
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Fatal("a store outage is not an AuthError refusal")
	}
	if !errors.Is(err, errStoreDown) {
		t.Fatal("the store's own error is the cause")
	}
	if store.holds(downJti) {
		t.Fatal("nothing was recorded for the SET the store could not answer for")
	}
	// Once the store answers, the same SET verifies: it was never judged.
	store.heal()
	if _, err := r.VerifySet(context.Background(), downSet); err != nil {
		t.Fatalf("after the store recovers the unjudged SET verifies: %v", err)
	}

	// Poll: a batch of three whose middle SET the store cannot answer for.
	stream := "s-store-" + uuid.NewString()
	a := with(setClaims(), "jti", "a-"+uuid.NewString())
	b := with(setClaims(), "jti", "b-"+uuid.NewString())
	c := with(setClaims(), "jti", "c-"+uuid.NewString())
	aJti, bJti, cJti := a["jti"].(string), b["jti"].(string), c["jti"].(string)
	s.mux.HandleFunc("/ssf/v1/poll/"+stream, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": map[string]any{
			aJti: key.signSet(t, a), bJti: key.signSet(t, b), cJti: key.signSet(t, c),
		}})
	})
	store.mu.Lock()
	store.broken = map[string]bool{bJti: true}
	store.mu.Unlock()
	result, err := r.Poll(context.Background(), stream, SsfPollOptions{})
	if err != nil {
		t.Fatalf("poll returns what it judged, with no error to drop it: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].Jti != aJti {
		t.Fatalf("the SET recorded before the store failed is returned: %+v", result.Events)
	}
	if len(result.Refused) != 0 {
		t.Fatalf("an unjudged SET is not refused, and above all not replayed: %+v", result.Refused)
	}
	if !reflect.DeepEqual(result.Unjudged, []string{bJti, cJti}) {
		t.Fatalf("the failed SET and the tail are unjudged: %v", result.Unjudged)
	}
	for _, event := range result.Events {
		if event.Jti == bJti || event.Jti == cJti {
			t.Fatal("an unjudged SET is not returned")
		}
	}
	if store.holds(bJti) || store.holds(cJti) {
		t.Fatal("an unjudged SET's jti is not recorded")
	}
	// A failed VerifySet, the healed one, then a and b (fails); c is not asked.
	if got := store.calls.Load(); got != 4 {
		t.Fatalf("the store is not asked again after it failed, got %d questions", got)
	}
	// The transmitter re-offers the unacknowledged SETs; the store has
	// recovered; they are judged now, and the one already returned reads
	// replayed (to be acknowledged, P2).
	store.heal()
	again, err := r.Poll(context.Background(), stream, SsfPollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Events) != 2 || again.Events[0].Jti != bJti || again.Events[1].Jti != cJti || len(again.Unjudged) != 0 {
		t.Fatalf("the unjudged SETs are judged on the next poll: %+v", again)
	}
	if len(again.Refused) != 1 || again.Refused[0].Jti != aJti || again.Refused[0].Reason != SetFailureReplayed {
		t.Fatalf("the SET returned earlier reads replayed: %+v", again.Refused)
	}
}

func TestSsfReceiver_TheStoreInterfaceIsFallible(t *testing.T) {
	// P4: an interface that answers a bare bool does not conform from 1.60.
	typ := reflect.TypeOf((*SsfReplayStore)(nil)).Elem()
	m, ok := typ.MethodByName("CheckAndRecord")
	if !ok || m.Type.NumOut() != 2 || m.Type.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("CheckAndRecord must return (bool, error): %v", m.Type)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(string(readme)), " ")
	for _, want := range []string{"unbounded in count", "gives no verdict"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("the README states the store rule: %q missing", want)
		}
	}
}
