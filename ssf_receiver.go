package axiam

// The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).
//
// AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
// security events as Security Event Tokens (RFC 8417) to the relying parties a
// tenant administrator registered (the §27 ssf namespace, Client.Ssf()). This
// file is for the RELYING PARTY that receives them, a different audience from
// that namespace:
//
//   - SsfReceiver.VerifySet verifies one compact SET — pushed to your endpoint
//     (RFC 8935) or returned by a poll — in the contract's fixed order and
//     refuses at the first failure with an *AuthError whose reason
//     SetFailureReasonOf reports.
//   - SsfReceiver.Poll calls the stream's poll endpoint (RFC 8936), verifies
//     every returned SET and hands back the verified and the refused apart.
//
// Neither transmits, signs or registers anything, and neither trusts a key it
// did not fetch from the configured JWKS: no `jwk` or `x5c` header member is
// honoured (§32.9).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// MinSsfReplayWindow is the replay window's floor and default: seven days, the
// transmitter's buffer retention (§32.6). A shorter window would forget a jti
// the transmitter can still re-send.
const MinSsfReplayWindow = 7 * 24 * time.Hour

// The two SSF stream event types (§32.6), beside the six AXIAM transmits
// (SsfEventTypeSessionRevoked … SsfEventTypeAccountPurged). Event types are
// open: a SET whose type is none of the eight still verifies, and
// SecurityEvent.EventType carries it verbatim.
const (
	SsfEventTypeVerification  SsfEventType = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	SsfEventTypeStreamUpdated SsfEventType = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

const (
	// ssfJWKSMaxAge is how long a fetched JWKS is used before an ordinary
	// refresh (the §10 verifier's cache ceiling). §34.2 P6 (contract 1.60)
	// bounds it at ten minutes after the successful fetch that filled it.
	ssfJWKSMaxAge = 300 * time.Second
	// ssfForcedRefetchInterval is the once-a-minute limit of §32.7 step 4 and
	// §34.2 P6: it counts every unknown-kid refetch, successful or not, and
	// every FAILED fill or refresh — never a successful one.
	ssfForcedRefetchInterval = 60 * time.Second
)

// SetFailureReason is why VerifySet refused a SET (§32.7's reason codes).
type SetFailureReason string

// The §32.7 reason codes, one per verification step.
const (
	// SetFailureMalformed: not three base64url parts decoding to a JSON header
	// and payload (step 1).
	SetFailureMalformed SetFailureReason = "malformed"
	// SetFailureInvalidType: the header typ is not secevent+jwt (step 2).
	SetFailureInvalidType SetFailureReason = "invalid_type"
	// SetFailureInvalidKey: alg not EdDSA, no key for kid after one refetch,
	// or a bad signature (steps 3–5).
	SetFailureInvalidKey SetFailureReason = "invalid_key"
	// SetFailureInvalidIssuer: iss is not the configured issuer (step 6).
	SetFailureInvalidIssuer SetFailureReason = "invalid_issuer"
	// SetFailureInvalidAudience: aud does not name the audience (step 7).
	SetFailureInvalidAudience SetFailureReason = "invalid_audience"
	// SetFailureInvalidRequest: exp or sub present, jti / iat / sub_id
	// absent, events not exactly one member (step 8).
	SetFailureInvalidRequest SetFailureReason = "invalid_request"
	// SetFailureReplayed: the jti was already seen inside the replay window
	// (step 9).
	SetFailureReplayed SetFailureReason = "replayed"
)

// PushErrorCode is the RFC 8935 §2.4 `err` to answer a push with, or to send
// in a poll's setErrs: the reason itself where RFC 8935 defines the code, and
// invalid_request for malformed, invalid_type and replayed, which it does not
// (RFC 8935 §2.4 defines invalid_request, invalid_key, invalid_issuer,
// invalid_audience, authentication_failed and access_denied).
func (r SetFailureReason) PushErrorCode() string {
	switch r {
	case SetFailureInvalidKey, SetFailureInvalidIssuer, SetFailureInvalidAudience:
		return string(r)
	}
	return string(SetFailureInvalidRequest)
}

// SetFailureReasonOf returns the reason VerifySet (or Poll) refused a SET for,
// and false for any other error — a JWKS fetch failure among them, which is
// not a verdict on the SET.
//
// A refusal found only beneath a *NetworkError is not one: that is a replay
// store which returned a refusal as its failure, and a store failure is no
// verdict (§34.2 P3).
func SetFailureReasonOf(err error) (SetFailureReason, bool) {
	for e := err; e != nil; e = errors.Unwrap(e) {
		switch v := e.(type) {
		case *NetworkError:
			return "", false
		case *AuthError:
			if v.setRefusal {
				return SetFailureReason(v.Reason), true
			}
		}
	}
	return "", false
}

func refuseSet(reason SetFailureReason, detail string) error {
	return &AuthError{
		Message:    fmt.Sprintf("SET refused (%s): %s (CONTRACT.md §32.7)", reason, detail),
		Reason:     string(reason),
		setRefusal: true,
	}
}

// SetErr is an RFC 8936 setErrs entry.
type SetErr struct {
	// Err is the RFC 8935 §2.4 code.
	Err string `json:"err"`
	// Description is optional text. AXIAM never stores it (§32.6).
	Description string `json:"description,omitempty"`
}

// NewSetErr is the setErrs entry for a refusal: its PushErrorCode.
func NewSetErr(reason SetFailureReason) SetErr {
	return SetErr{Err: reason.PushErrorCode()}
}

// SsfReplayStore remembers the jtis already accepted, for step 9. Pluggable so
// a receiver running several instances can share one store (§32.7).
//
// A store has THREE answers — new, already seen, and CANNOT ANSWER — and the
// third is the error result (contract 1.60 §34.2 P4, which withdrew 1.59's
// "answer already-seen when you cannot" route: it turned a store outage into a
// replayed refusal that a caller then acknowledges, so an event that was never
// processed was lost). A store that cannot answer — a shared cache that is
// down, a timeout, a lost connection — returns a non-nil error. That gives NO
// VERDICT: the SET is neither refused nor accepted, VerifySet returns a
// *NetworkError with no SetFailureReason, and Poll leaves the SET unjudged
// (SsfPollResult.Unjudged): not recorded, not returned, not refused, so the
// transmitter offers it again.
type SsfReplayStore interface {
	// CheckAndRecord records jti for window and returns (true, nil), or
	// returns (false, nil) without recording when it is already held. It MUST
	// be atomic: two concurrent calls with one jti must not both see true.
	// When the store cannot answer it returns a non-nil error and records
	// nothing; the bool is then ignored.
	CheckAndRecord(jti string, window time.Duration) (bool, error)
}

// MemorySsfReplayStore is the in-memory SsfReplayStore: one process, lost on
// restart. The zero value is ready to use. It is bounded in time — an entry
// is dropped once its window has passed — but unbounded in count (§34.2 P4).
type MemorySsfReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// CheckAndRecord implements SsfReplayStore, dropping expired entries first.
// It never fails: a map in this process always answers.
func (s *MemorySsfReplayStore) CheckAndRecord(jti string, window time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	for k, expires := range s.seen {
		if !expires.After(now) {
			delete(s.seen, k)
		}
	}
	if _, held := s.seen[jti]; held {
		return false, nil
	}
	s.seen[jti] = now.Add(window)
	return true, nil
}

// SsfAccessTokenProvider supplies the bearer Poll presents: a
// client-credentials access token carrying ssf.manage (for example
// LoginClientCredentials' AccessToken). Called once per Poll.
type SsfAccessTokenProvider func(ctx context.Context) (Sensitive, error)

// SsfReceiverConfig configures an SsfReceiver (§32.7: { issuer, audience,
// jwks_uri | discovery_url, access_token_provider }).
type SsfReceiverConfig struct {
	// Issuer is the transmitter's issuer, compared to iss exactly. Required.
	Issuer string
	// Audience is this receiver's audience — the stream's audience. Required.
	Audience string
	// JWKSURI is the transmitter's JWKS URL (AXIAM: {issuer}/oauth2/jwks).
	// Exactly one of JWKSURI and DiscoveryURL.
	JWKSURI string
	// DiscoveryURL is the transmitter's SSF configuration document
	// (/.well-known/ssf-configuration…); its jwks_uri is used, and its issuer
	// must equal Issuer. Exactly one of JWKSURI and DiscoveryURL.
	DiscoveryURL string
	// AccessTokenProvider is the bearer for Poll; nil for a push-only
	// receiver.
	AccessTokenProvider SsfAccessTokenProvider
	// ReplayWindow is how long a jti is remembered. Zero means
	// MinSsfReplayWindow; anything below it is refused at construction.
	ReplayWindow time.Duration
	// ReplayStore keeps the accepted jtis; nil uses a MemorySsfReplayStore.
	ReplayStore SsfReplayStore
}

// SecurityEvent is a verified Security Event Token (§32.7's result).
type SecurityEvent struct {
	// Jti is the SET's unique id.
	Jti string
	// Iat is when it was issued, seconds since the epoch.
	Iat int64
	// Iss is the issuer, equal to the configured one.
	Iss string
	// Aud is the audience as sent: one string, or an array containing yours.
	Aud json.RawMessage
	// Txn is the transaction id shared by every SET one operation produced;
	// "" when absent.
	Txn string
	// EventType is the single events key — an event-type URI.
	EventType SsfEventType
	// Event is that event's object, opaque to the helper.
	Event json.RawMessage
	// SubID is the RFC 9493 subject identifier, opaque to the helper.
	SubID json.RawMessage
}

// RefusedSet is one SET a poll returned and the helper refused.
type RefusedSet struct {
	// Jti is the key the transmitter returned the SET under.
	Jti string
	// Reason is why it was refused. Pass NewSetErr(Reason) in the next poll's
	// SetErrs — except SetFailureReplayed: this receiver accepted that SET
	// earlier, so acknowledge it in Ack instead (§34.2 P2).
	Reason SetFailureReason
}

// SsfPollOptions are Poll's arguments. Every member is passed through as
// given; an unset (nil) one is not sent.
type SsfPollOptions struct {
	// MaxEvents is maxEvents — the server clamps it to 100; 0 acknowledges and
	// returns nothing.
	MaxEvents *int
	// ReturnImmediately is returnImmediately — without it the server
	// long-polls up to 30 s.
	ReturnImmediately *bool
	// Ack is the jtis you PROCESSED since the last poll. A non-nil empty slice
	// is sent as [].
	Ack []string
	// SetErrs is the jtis you refuse, each with its code.
	SetErrs map[string]SetErr
}

// SsfPollResult is what Poll returns.
type SsfPollResult struct {
	// Events are the SETs that verified, ordered by jti.
	Events []SecurityEvent
	// MoreAvailable reports whether the transmitter holds more.
	MoreAvailable bool
	// Refused are the SETs that did not verify, ordered by jti.
	Refused []RefusedSet
	// Unjudged are the jtis of SETs that verified (steps 1–8) but that the
	// replay store could not answer for (§34.2 P1, P4): in neither Events nor
	// Refused, NOT recorded. Acknowledge none of them and report none in
	// SetErrs — the transmitter offers them again. Nil when the store answered
	// for every SET. Ordered by jti.
	Unjudged []string
}

type ssfKey struct {
	public ed25519.PublicKey // nil: present in the JWKS, but not an Ed25519 key
}

// SsfReceiver is the §32.7 receiver helper. Build one with NewSsfReceiver; it
// is safe for concurrent use.
type SsfReceiver struct {
	client       *Client
	issuer       string
	audience     string
	discoveryURL string
	tokens       SsfAccessTokenProvider
	window       time.Duration
	store        SsfReplayStore

	mu        sync.Mutex
	jwksURI   string
	keys      map[string]ssfKey
	fetchedAt time.Time
	// lastCounted is the last fetch the once-a-minute limit counts (P6).
	lastCounted time.Time
	now         func() time.Time
}

// NewSsfReceiver builds a receiver over client's transport — its §6 TLS
// policy fetches the JWKS, and its base URL is the transmitter root Poll
// calls. No request is made here.
//
// A local *ValidationError when Issuer or Audience is empty, when not exactly
// one of JWKSURI and DiscoveryURL is set or it is not an https URL (http only
// on a loopback host), or when ReplayWindow is below MinSsfReplayWindow.
func NewSsfReceiver(client *Client, config SsfReceiverConfig) (*SsfReceiver, error) {
	const operation = "ssf.receiver"
	if client == nil {
		return nil, localRefusal(operation, "client", "a *Client is required")
	}
	if config.Issuer == "" || config.Audience == "" {
		return nil, localRefusal(operation, "issuer", "issuer and audience are required (CONTRACT.md §32.7)")
	}
	window := config.ReplayWindow
	if window == 0 {
		window = MinSsfReplayWindow
	}
	if window < MinSsfReplayWindow {
		return nil, localRefusal(operation, "replay_window",
			"must be at least seven days, the transmitter's buffer retention (CONTRACT.md §32.7)")
	}
	if (config.JWKSURI == "") == (config.DiscoveryURL == "") {
		return nil, localRefusal(operation, "jwks_uri", "set exactly one of jwks_uri and discovery_url (CONTRACT.md §32.7)")
	}
	for field, raw := range map[string]string{"jwks_uri": config.JWKSURI, "discovery_url": config.DiscoveryURL} {
		if raw == "" {
			continue
		}
		if !isSecureFetchURL(raw) {
			return nil, localRefusal(operation, field, "must be an absolute https URL (http only on a loopback host)")
		}
	}
	store := config.ReplayStore
	if store == nil {
		store = &MemorySsfReplayStore{}
	}
	return &SsfReceiver{
		client:       client,
		issuer:       config.Issuer,
		audience:     config.Audience,
		discoveryURL: config.DiscoveryURL,
		jwksURI:      config.JWKSURI,
		tokens:       config.AccessTokenProvider,
		window:       window,
		store:        store,
		now:          time.Now,
	}, nil
}

// isSecureFetchURL accepts an absolute https URL, or http on a loopback host.
func isSecureFetchURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		return isLoopbackHost(strings.ToLower(u.Hostname()))
	}
	return false
}

// String renders the receiver's configuration — never the token provider.
func (r *SsfReceiver) String() string {
	return fmt.Sprintf("SsfReceiver{issuer: %s, audience: %s, replay_window: %s}", r.issuer, r.audience, r.window)
}

// getJSON fetches rawURL on the bare transport (no cookies, no redirects) and
// decodes it into out. Every failure is a *NetworkError.
func (r *SsfReceiver) getJSON(ctx context.Context, what, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return &NetworkError{Message: what + ": could not build the request"}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.bareHTTPClient().Do(req)
	if err != nil {
		return newNetworkError(what+" fetch failed", nil, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newNetworkError(fmt.Sprintf("%s fetch failed with HTTP %d", what, resp.StatusCode), resp, nil)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return &NetworkError{Message: fmt.Sprintf("%s: the response is not the expected JSON", what)}
	}
	return nil
}

// resolveJWKSURI returns the configured jwks_uri, or the discovery document's
// (fetched once, its issuer checked). Called with r.mu held.
func (r *SsfReceiver) resolveJWKSURI(ctx context.Context) (string, error) {
	if r.jwksURI != "" {
		return r.jwksURI, nil
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := r.getJSON(ctx, "SSF configuration", r.discoveryURL, &doc); err != nil {
		return "", err
	}
	if doc.Issuer != r.issuer {
		return "", &NetworkError{Message: "the SSF configuration's issuer is not the configured issuer (CONTRACT.md §32.7)"}
	}
	if doc.JWKSURI == "" || !isSecureFetchURL(doc.JWKSURI) {
		return "", &NetworkError{Message: "the SSF configuration carries no usable https jwks_uri"}
	}
	r.jwksURI = doc.JWKSURI
	return r.jwksURI, nil
}

// fetchKeys replaces the cached key set. Called with r.mu held.
func (r *SsfReceiver) fetchKeys(ctx context.Context) error {
	jwksURI, err := r.resolveJWKSURI(ctx)
	if err != nil {
		return err
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := r.getJSON(ctx, "JWKS", jwksURI, &set); err != nil {
		return err
	}
	keys := make(map[string]ssfKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" {
			continue
		}
		entry := ssfKey{}
		if k.Kty == "OKP" && k.Crv == "Ed25519" {
			if raw, err := base64.RawURLEncoding.DecodeString(k.X); err == nil && len(raw) == ed25519.PublicKeySize {
				entry.public = ed25519.PublicKey(raw)
			}
		}
		keys[k.Kid] = entry
	}
	r.keys = keys
	r.fetchedAt = r.now()
	return nil
}

// keyFor is step 4: the key named by kid, with one forced refetch on a miss.
// found is false when the kid is still unknown.
//
// The once-a-minute limit (§34.2 P6) counts the unknown-kid refetch whether
// or not it succeeds, and a fill or expiry refresh only when it FAILS: a JWKS
// outage costs one fetch a minute, not one per SET. Inside the minute after a
// failed fetch, a cache that needs filling makes no fetch and the SET gets no
// verdict — a *NetworkError with no reason code, like the failed fetch itself.
func (r *SsfReceiver) keyFor(ctx context.Context, kid string) (ssfKey, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil || r.now().Sub(r.fetchedAt) > ssfJWKSMaxAge {
		if r.limited() {
			return ssfKey{}, false, &NetworkError{Message: "ssf.receiver: the JWKS fetch failed less than a minute ago " +
				"and is not retried yet: the SET is unjudged (CONTRACT.md §34.2 P6)"}
		}
		if err := r.fetchKeys(ctx); err != nil {
			r.lastCounted = r.now()
			return ssfKey{}, false, err
		}
	}
	if key, ok := r.keys[kid]; ok {
		return key, true, nil
	}
	if r.limited() {
		return ssfKey{}, false, nil
	}
	r.lastCounted = r.now()
	if err := r.fetchKeys(ctx); err != nil {
		return ssfKey{}, false, err
	}
	key, ok := r.keys[kid]
	return key, ok, nil
}

// limited reports whether a counted fetch happened within the last minute.
// Called with r.mu held.
func (r *SsfReceiver) limited() bool {
	return !r.lastCounted.IsZero() && r.now().Sub(r.lastCounted) < ssfForcedRefetchInterval
}

// decodeObject base64url-decodes part and parses it as a JSON object.
func decodeObject(part string) (map[string]json.RawMessage, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, false
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, false
	}
	return out, true
}

func rawString(raw json.RawMessage) (string, bool) {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// VerifySet verifies one compact SET (§32.7), in this order, refusing at the
// first failure with the reason in brackets:
//
//  1. three base64url parts, a JSON-object header and payload [malformed];
//  2. typ secevent+jwt or application/secevent+jwt, any case [invalid_type];
//  3. alg exactly EdDSA [invalid_key];
//  4. the kid in the configured JWKS — on a miss, one refetch, at most once a
//     minute [invalid_key];
//  5. the Ed25519 signature [invalid_key];
//  6. iss equal to the configured issuer [invalid_issuer];
//  7. aud equal to, or an array containing, the audience [invalid_audience];
//  8. no exp, no sub; a non-empty string jti, a numeric iat, an object
//     sub_id; events an object with exactly one member [invalid_request];
//  9. a jti not seen within the replay window [replayed] — recorded only once
//     steps 1–8 passed.
//
// A SET that verifies has been RECORDED: verifying it again is replayed.
// Acknowledge a polled SET once you have processed it.
//
// A refusal is an *AuthError for which SetFailureReasonOf reports the reason;
// answer a push with `400 {"err": reason.PushErrorCode()}`. A JWKS fetch
// failure, and a replay store that cannot answer (SsfReplayStore), are a
// *NetworkError instead — not a verdict on the SET: answer a push with a 5xx.
func (r *SsfReceiver) VerifySet(ctx context.Context, set string) (SecurityEvent, error) {
	event, err := r.judge(ctx, set, nil)
	if err != nil {
		return SecurityEvent{}, err
	}
	return r.record(event)
}

// record is step 9: the jti is recorded only once steps 1–8 passed.
func (r *SsfReceiver) record(event SecurityEvent) (SecurityEvent, error) {
	fresh, err := r.store.CheckAndRecord(event.Jti, r.window)
	if err != nil {
		return SecurityEvent{}, errReplayStoreUnavailable(err)
	}
	if !fresh {
		return SecurityEvent{}, refuseSet(SetFailureReplayed, "the jti was already seen")
	}
	return event, nil
}

// errReplayStoreUnavailable is the error for a replay store that cannot answer
// (§34.2 P3/P4): the §2 NetworkError, no reason code — SetFailureReasonOf
// reports false — so a push endpoint answers a 5xx and the transmitter retries.
// The store's own error is the cause, reachable with errors.Is/As.
//
// Contract 1.60 (C-1): one of this SDK's own §2 errors returned by the store
// passes through unchanged — except a §32.7 refusal, which is wrapped like any
// other failure (the MAY of P3), so that no store failure surfaces carrying a
// reason code.
func errReplayStoreUnavailable(cause error) error {
	switch e := cause.(type) {
	case *AuthError:
		if !e.setRefusal {
			return cause
		}
	case *AuthzError, *NetworkError, *OAuthProtocolError, *NotFoundError, *ConflictError, *ValidationError:
		return cause
	}
	return &NetworkError{
		Message: "the replay store could not answer: the SET is unjudged, not refused and not accepted (CONTRACT.md §32.7 step 9)",
		cause:   cause,
	}
}

// judge is steps 1–8. It records nothing.
func (r *SsfReceiver) judge(ctx context.Context, set string, expectedJti *string) (SecurityEvent, error) {
	// 1.
	parts := strings.Split(set, ".")
	if len(parts) != 3 {
		return SecurityEvent{}, refuseSet(SetFailureMalformed, "not three base64url parts")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return SecurityEvent{}, refuseSet(SetFailureMalformed, "the signature is not base64url")
	}
	header, okHeader := decodeObject(parts[0])
	claims, okClaims := decodeObject(parts[1])
	if !okHeader || !okClaims {
		return SecurityEvent{}, refuseSet(SetFailureMalformed, "the header or payload is not a JSON object")
	}
	// 2.
	typ, _ := rawString(header["typ"])
	if !strings.EqualFold(typ, "secevent+jwt") && !strings.EqualFold(typ, "application/secevent+jwt") {
		return SecurityEvent{}, refuseSet(SetFailureInvalidType, "typ is not secevent+jwt")
	}
	// 3.
	if alg, _ := rawString(header["alg"]); alg != "EdDSA" {
		return SecurityEvent{}, refuseSet(SetFailureInvalidKey, "alg is not EdDSA")
	}
	// 4.
	kid, ok := rawString(header["kid"])
	if !ok {
		return SecurityEvent{}, refuseSet(SetFailureInvalidKey, "no kid")
	}
	key, found, err := r.keyFor(ctx, kid)
	if err != nil {
		return SecurityEvent{}, err
	}
	if !found {
		return SecurityEvent{}, refuseSet(SetFailureInvalidKey, "no key for the kid in the JWKS")
	}
	if key.public == nil {
		return SecurityEvent{}, refuseSet(SetFailureInvalidKey, "the JWKS key for the kid is not an Ed25519 key")
	}
	// 5.
	if !ed25519.Verify(key.public, []byte(parts[0]+"."+parts[1]), signature) {
		return SecurityEvent{}, refuseSet(SetFailureInvalidKey, "the signature does not verify")
	}
	// 6.
	iss, _ := rawString(claims["iss"])
	if iss != r.issuer {
		return SecurityEvent{}, refuseSet(SetFailureInvalidIssuer, "iss is not the configured issuer")
	}
	// 7.
	if !audienceNames(claims["aud"], r.audience) {
		return SecurityEvent{}, refuseSet(SetFailureInvalidAudience, "aud does not name this receiver")
	}
	// 8.
	if _, has := claims["exp"]; has {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "a SET carries no exp")
	}
	if _, has := claims["sub"]; has {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "a SET carries no sub")
	}
	jti, ok := rawString(claims["jti"])
	if !ok || jti == "" {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "no jti")
	}
	var iat int64
	if raw := claims["iat"]; raw == nil || json.Unmarshal(raw, &iat) != nil {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "no numeric iat")
	}
	subID := claims["sub_id"]
	if !isJSONObject(subID) {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "no sub_id object")
	}
	var events map[string]json.RawMessage
	if raw := claims["events"]; raw == nil || json.Unmarshal(raw, &events) != nil || len(events) != 1 {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "events must have exactly one member")
	}
	if expectedJti != nil && *expectedJti != jti {
		return SecurityEvent{}, refuseSet(SetFailureInvalidRequest, "the poll key is not the SET's jti")
	}
	var eventType string
	var event json.RawMessage
	for k, v := range events {
		eventType, event = k, v
	}
	txn, _ := rawString(claims["txn"])
	return SecurityEvent{
		Jti:       jti,
		Iat:       iat,
		Iss:       iss,
		Aud:       claims["aud"],
		Txn:       txn,
		EventType: SsfEventType(eventType),
		Event:     event,
		SubID:     subID,
	}, nil
}

func isJSONObject(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	return raw != nil && json.Unmarshal(raw, &obj) == nil && obj != nil
}

// audienceNames is step 7: aud is the audience, or an array containing it.
func audienceNames(raw json.RawMessage, audience string) bool {
	if s, ok := rawString(raw); ok {
		return s == audience
	}
	var items []json.RawMessage
	if raw == nil || json.Unmarshal(raw, &items) != nil {
		return false
	}
	for _, item := range items {
		if s, ok := rawString(item); ok && s == audience {
			return true
		}
	}
	return false
}

// Poll calls the stream's RFC 8936 endpoint, {base URL}/ssf/v1/poll/{streamID},
// with a bearer from the configured AccessTokenProvider (none: a local
// *AuthError), on the bare transport — no SDK session, no cookies, no
// redirects.
//
// options.Ack and options.SetErrs are sent EXACTLY as given, and only the
// members set. NOTHING IS ACKNOWLEDGED ON YOUR BEHALF: acknowledge, on the next
// call, the jtis you processed, and pass each refused one in SetErrs
// (NewSetErr) — except a replayed one, which this receiver accepted earlier:
// acknowledge that one (§34.2 P2). A SET you neither acknowledge nor refuse is
// re-offered, and — having been recorded when it was returned — then reads as
// replayed.
//
// Retried per §16 on a transport failure, a 5xx, a 408 or a 429 — never on
// another 4xx, which maps as the management API's do (400 → *ValidationError,
// 404 → *NotFoundError, 401 → *AuthError …).
//
// Poll NEVER KEEPS A JTI IT DOES NOT RETURN (§32.7, §34.2 P1): steps 1–8 run
// over the whole batch before any jti is recorded. A failure that is no
// verdict on a SET — a JWKS or discovery fetch that fails — aborts the poll
// with that error having recorded nothing, so the transmitter offers the
// whole batch again and no event is lost.
//
// A replay store that CANNOT ANSWER (CheckAndRecord returns an error) gives no
// verdict (§34.2 P4): Poll returns what it judged, with a nil error so the
// SETs it did record are not dropped, and lists the SETs it could not judge in
// SsfPollResult.Unjudged — recorded nowhere, in neither Events nor Refused.
// Do not acknowledge them.
func (r *SsfReceiver) Poll(ctx context.Context, streamID string, options SsfPollOptions) (SsfPollResult, error) {
	const operation = "ssf.poll"
	if err := r.client.ensureOpen(); err != nil {
		return SsfPollResult{}, err
	}
	if r.tokens == nil {
		return SsfPollResult{}, &AuthError{Message: "ssf.poll needs an AccessTokenProvider (a client-credentials token with ssf.manage) (CONTRACT.md §32.7)"}
	}
	body := map[string]any{}
	if options.MaxEvents != nil {
		body["maxEvents"] = *options.MaxEvents
	}
	if options.ReturnImmediately != nil {
		body["returnImmediately"] = *options.ReturnImmediately
	}
	if options.Ack != nil {
		body["ack"] = options.Ack
	}
	if options.SetErrs != nil {
		body["setErrs"] = options.SetErrs
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return SsfPollResult{}, localRefusal(operation, "options", "could not be encoded as JSON")
	}
	token, err := r.tokens(ctx)
	if err != nil {
		return SsfPollResult{}, err
	}

	target := *r.client.baseURL
	basePath := strings.TrimRight(target.Path, "/")
	baseRaw := strings.TrimRight(target.EscapedPath(), "/")
	target.Path = basePath + "/ssf/v1/poll/" + streamID
	target.RawPath = baseRaw + "/ssf/v1/poll/" + url.PathEscape(streamID)
	target.RawQuery = ""

	var (
		reply    []byte
		decisive error
	)
	retryErr := r.client.retryReadOnly(ctx, operation, func(ctx context.Context, _ int) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(encoded))
		if err != nil {
			decisive = &NetworkError{Message: operation + ": could not build the request"}
			return errStopRetry
		}
		req.Header.Set("Authorization", "Bearer "+token.expose())
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := r.client.bareHTTPClient().Do(req)
		if err != nil {
			return newNetworkError(operation+": request failed", nil, nil)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			mapped := managementError(operation, resp, raw)
			if netErr, ok := mapped.(*NetworkError); ok {
				netErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			}
			if !statusIsRetryable(resp.StatusCode) {
				decisive = mapped
				return errStopRetry
			}
			return mapped
		}
		if readErr != nil {
			return newNetworkError(operation+": could not read the response", nil, nil)
		}
		reply = raw
		return nil
	})
	if decisive != nil {
		return SsfPollResult{}, decisive
	}
	if retryErr != nil {
		return SsfPollResult{}, retryErr
	}

	var wire struct {
		Sets          map[string]json.RawMessage `json:"sets"`
		MoreAvailable bool                       `json:"moreAvailable"`
	}
	if err := json.Unmarshal(reply, &wire); err != nil {
		return SsfPollResult{}, &NetworkError{Message: operation + ": the response is not a poll answer"}
	}
	result := SsfPollResult{MoreAvailable: wire.MoreAvailable}
	jtis := make([]string, 0, len(wire.Sets))
	for jti := range wire.Sets {
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)
	// §34.2 P1, first form: steps 1–8 run over the WHOLE batch before any jti
	// is recorded. A failure that is no verdict on a SET (a JWKS or discovery
	// fetch) aborts the poll having recorded nothing, so every SET of the
	// batch is offered again rather than read as replayed and lost.
	judged := make([]SecurityEvent, 0, len(jtis))
	for _, jti := range jtis {
		set, ok := rawString(wire.Sets[jti])
		if !ok {
			result.Refused = append(result.Refused, RefusedSet{Jti: jti, Reason: SetFailureMalformed})
			continue
		}
		event, err := r.judge(ctx, set, &jti)
		if err == nil {
			judged = append(judged, event)
			continue
		}
		reason, refused := SetFailureReasonOf(err)
		if !refused {
			return SsfPollResult{}, err
		}
		result.Refused = append(result.Refused, RefusedSet{Jti: jti, Reason: reason})
	}
	// Step 9, only now: every SET recorded here is returned in Events. A store
	// that cannot answer gives no verdict (§34.2 P4): the SET and the rest of
	// the tail are left UNJUDGED — second form of P1, since the store has an
	// atomic check-and-record and no un-record, so what it recorded earlier in
	// this loop is returned and what it did not is not recorded. The store is
	// not asked again in this call.
	for i, event := range judged {
		_, err := r.record(event)
		if err == nil {
			result.Events = append(result.Events, event)
			continue
		}
		if _, refused := SetFailureReasonOf(err); refused {
			result.Refused = append(result.Refused, RefusedSet{Jti: event.Jti, Reason: SetFailureReplayed})
			continue
		}
		for _, rest := range judged[i:] {
			result.Unjudged = append(result.Unjudged, rest.Jti)
		}
		break
	}
	sort.Slice(result.Refused, func(i, j int) bool { return result.Refused[i].Jti < result.Refused[j].Jti })
	if len(result.Unjudged) > 0 {
		// §19.1 (contract 1.60): an outage the caller sees in no error is
		// made visible. Only the store can leave SETs unjudged on a normal
		// return here — a failed key fetch aborts the poll above.
		r.client.telemetry.emit(SsfUnjudgedEvent{Operation: operation, Count: len(result.Unjudged),
			Category: SsfUnjudgedReplayStore})
	}
	return result, nil
}
