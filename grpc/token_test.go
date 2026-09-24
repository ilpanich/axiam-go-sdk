package grpc

import (
	"context"
	"errors"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	axiam "github.com/ilpanich/axiam-go-sdk"
	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// TestTokenGrpcClient_ValidateToken_FullFieldSet proves §1.1.1 rule 3: every
// response field is modeled, including cnf.
func TestTokenGrpcClient_ValidateToken_FullFieldSet(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{
		Valid:     true,
		SubjectId: "subject-uuid",
		TenantId:  "tenant-uuid",
		OrgId:     "org-uuid",
		Exp:       1700000000,
		Cnf:       &axiamv1.CnfClaim{X5TS256: "thumbprint-abc"},
		TokenType: "Bearer",
	}}}

	v, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("caller-tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !v.Valid || v.SubjectID != "subject-uuid" || v.TenantID != "tenant-uuid" || v.OrgID != "org-uuid" || v.Exp != 1700000000 || v.TokenType != "Bearer" {
		t.Fatalf("fields not mapped: %+v", v)
	}
	if v.Cnf == nil || v.Cnf.X5tS256 != "thumbprint-abc" {
		t.Fatalf("cnf not mapped: %+v", v.Cnf)
	}
}

// TestTokenGrpcClient_IntrospectToken_FullFieldSet proves the RFC 7662 set
// plus cnf/permissions/ext_exchange_iss are all modeled.
func TestTokenGrpcClient_IntrospectToken_FullFieldSet(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.IntrospectTokenResponse{
		Active:    true,
		Sub:       "subject-uuid",
		TenantId:  "tenant-uuid",
		OrgId:     "org-uuid",
		Iss:       "https://axiam.example.com",
		Iat:       1699999000,
		Exp:       1700000000,
		Jti:       "jti-uuid",
		Scope:     "authz:check",
		ClientId:  "client-abc",
		TokenType: "Bearer",
		Cnf:       &axiamv1.CnfClaim{Jkt: "jkt-xyz"},
		Permissions: []*axiamv1.RptPermission{
			{ResourceId: "res-1", ResourceScopes: []string{"read", "write"}, Exp: 1700000100},
		},
		ExtExchangeIss: "https://partner.example.com",
	}}}

	i, err := NewTokenGrpcClient(conn, nil, nil).IntrospectToken(context.Background(), axiam.Sensitive("caller-tok"))
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !i.Active || i.Sub != "subject-uuid" || i.TenantID != "tenant-uuid" || i.OrgID != "org-uuid" ||
		i.Iss != "https://axiam.example.com" || i.Iat != 1699999000 || i.Exp != 1700000000 ||
		i.Jti != "jti-uuid" || i.Scope != "authz:check" || i.ClientID != "client-abc" ||
		i.TokenType != "Bearer" || i.ExtExchangeIss != "https://partner.example.com" {
		t.Fatalf("RFC 7662 fields not mapped: %+v", i)
	}
	if i.Cnf == nil || i.Cnf.Jkt != "jkt-xyz" {
		t.Fatalf("cnf not mapped: %+v", i.Cnf)
	}
	if len(i.Permissions) != 1 || i.Permissions[0].ResourceID != "res-1" || len(i.Permissions[0].ResourceScopes) != 2 || i.Permissions[0].Exp != 1700000100 {
		t.Fatalf("permissions not mapped: %+v", i.Permissions)
	}
}

// TestTokenGrpcClient_NoCallerTokenRefusesWithZeroWireCalls is §1.1.1 rule
// 2: with no caller token, both operations fail client-side with
// *axiam.AuthError and make ZERO wire calls — the twin of the case where a
// caller token IS present (covered by every other test in this file, which
// all supply hasToken=nil, "not checked", and separately by the "caller
// token present" subtest below with hasToken returning true).
func TestTokenGrpcClient_NoCallerTokenRefusesWithZeroWireCalls(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{Valid: true}}}
	client := NewTokenGrpcClient(conn, func() bool { return false }, nil)

	t.Run("ValidateToken", func(t *testing.T) {
		_, err := client.ValidateToken(context.Background(), axiam.Sensitive("inspected-tok"))
		if err == nil {
			t.Fatal("expected an error with no caller token")
		}
		if _, ok := err.(*axiam.AuthError); !ok {
			t.Fatalf("got %T, want *axiam.AuthError", err)
		}
		if conn.calls != 0 {
			t.Fatalf("expected ZERO wire calls, got %d", conn.calls)
		}
	})

	t.Run("IntrospectToken", func(t *testing.T) {
		_, err := client.IntrospectToken(context.Background(), axiam.Sensitive("inspected-tok"))
		if err == nil {
			t.Fatal("expected an error with no caller token")
		}
		if _, ok := err.(*axiam.AuthError); !ok {
			t.Fatalf("got %T, want *axiam.AuthError", err)
		}
		if conn.calls != 0 {
			t.Fatalf("expected ZERO wire calls, got %d", conn.calls)
		}
	})
}

// TestTokenGrpcClient_CallerTokenPresentReachesTheWire is the I4 twin of
// the test above: hasToken reporting true lets the call proceed normally.
func TestTokenGrpcClient_CallerTokenPresentReachesTheWire(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{Valid: true}}}
	client := NewTokenGrpcClient(conn, func() bool { return true }, nil)

	if _, err := client.ValidateToken(context.Background(), axiam.Sensitive("inspected-tok")); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 wire call, got %d", conn.calls)
	}
}

// TestTokenGrpcClient_TwoTokensStayApart proves rule 1: the inspected
// token travels in the request message's access_token field, never
// defaulted from — or confused with — the caller's own bearer credential
// (which the interceptor attaches out of band and this test cannot even
// see from here, underscoring that there is no code path by which the two
// could be conflated).
func TestTokenGrpcClient_TwoTokensStayApart(t *testing.T) {
	var capturedAccessToken string
	conn := &recordingConn{
		record: func(req proto.Message) {
			if r, ok := req.(*axiamv1.ValidateTokenRequest); ok {
				capturedAccessToken = r.GetAccessToken()
			}
		},
		reply: &axiamv1.ValidateTokenResponse{Valid: true},
	}

	if _, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("the-inspected-token")); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if capturedAccessToken != "the-inspected-token" {
		t.Fatalf("access_token = %q, want %q", capturedAccessToken, "the-inspected-token")
	}
}

// TestTokenGrpcClient_EmptyCnfIsRefusedNotUnbound is §10.3 rule 3: a
// CnfClaim with both members empty is proto3's spelling of "an empty {}
// object", not "absent" — it MUST be refused, never read as unbound. This
// is also this SDK's own regression guard: an EARLIER version of
// Confirmation.Verify (mutation-tested below) read an empty confirmation as
// unbound, which turns this test red.
func TestTokenGrpcClient_EmptyCnfIsRefusedNotUnbound(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{
		Valid: true,
		Cnf:   &axiamv1.CnfClaim{}, // present, both fields empty
	}}}

	v, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if v.Cnf == nil {
		t.Fatal("an empty CnfClaim must still map to a NON-NIL *Confirmation — the distinction from absent lives in Verify, not in the mapping")
	}
	if v.Status() != TokenUnverifiable {
		t.Fatalf("Status() = %v, want TokenUnverifiable for a present-but-empty cnf", v.Status())
	}
	err = v.VerifyPossession(axiam.PresentedProofs{CertificateThumbprint: "anything", DPoPThumbprint: "anything"})
	if err == nil {
		t.Fatal("VerifyPossession must refuse a present-but-empty cnf, not accept it as unbound")
	}
}

// TestTokenGrpcClient_UnboundResponseStillValidates is §10.3's required
// positive regression: a response with no cnf at all (every pre-1.17
// server, and every unbound token since) is accepted.
func TestTokenGrpcClient_UnboundResponseStillValidates(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{Valid: true}}}

	v, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if v.Cnf != nil {
		t.Fatalf("expected nil Cnf for an unbound token, got %+v", v.Cnf)
	}
	if v.Status() != TokenBearer {
		t.Fatalf("Status() = %v, want TokenBearer", v.Status())
	}
	if err := v.VerifyPossession(axiam.PresentedProofs{}); err != nil {
		t.Fatalf("an unbound token must verify with NO proofs at all, got %v", err)
	}
}

// TestTokenGrpcClient_BoundTokenNotUsableWithoutMatchingProof is §10.3 rule
// 2 / §1.1.1 rule 4: valid:true with cnf present is not "usable as
// presented" until VerifyPossession confirms THIS caller's own connection.
func TestTokenGrpcClient_BoundTokenNotUsableWithoutMatchingProof(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{
		Valid: true,
		Cnf:   &axiamv1.CnfClaim{X5TS256: "expected-thumbprint"},
	}}}

	v, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if v.Status() != TokenUnverifiable {
		t.Fatalf("Status() before verification = %v, want TokenUnverifiable", v.Status())
	}
	if err := v.VerifyPossession(axiam.PresentedProofs{}); err == nil {
		t.Fatal("expected VerifyPossession to refuse with no certificate presented")
	}
	if err := v.VerifyPossession(axiam.PresentedProofs{CertificateThumbprint: "wrong-thumbprint"}); err == nil {
		t.Fatal("expected VerifyPossession to refuse with a MISMATCHED certificate")
	}
	if err := v.VerifyPossession(axiam.PresentedProofs{CertificateThumbprint: "expected-thumbprint"}); err != nil {
		t.Fatalf("expected VerifyPossession to accept the MATCHING certificate, got %v", err)
	}
}

// TestTokenGrpcClient_TokenTypeDoesNotSayBoundness is §1.1.1 rule 5: a
// certificate-bound device token is reported token_type="Bearer", never
// "DPoP" — Status()/VerifyPossession must decide from Cnf alone.
func TestTokenGrpcClient_TokenTypeDoesNotSayBoundness(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.ValidateTokenResponse{
		Valid:     true,
		TokenType: "Bearer",
		Cnf:       &axiamv1.CnfClaim{X5TS256: "device-cert-thumbprint"},
	}}}

	v, err := NewTokenGrpcClient(conn, nil, nil).ValidateToken(context.Background(), axiam.Sensitive("device-tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if v.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", v.TokenType)
	}
	if v.Status() == TokenBearer {
		t.Fatal("a certificate-bound token reported token_type=Bearer must NOT read as TokenBearer — boundness comes from Cnf, not TokenType")
	}
}

// TestTokenGrpcClient_AnotherTenantsTokenIsAnAnswerNotAnError is §10.3
// rule... via §1.1.1 rule 6: valid:false / active:false for a token of
// another tenant is a normal result, never an error.
func TestTokenGrpcClient_AnotherTenantsTokenIsAnAnswerNotAnError(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.IntrospectTokenResponse{Active: false}}}

	i, err := NewTokenGrpcClient(conn, nil, nil).IntrospectToken(context.Background(), axiam.Sensitive("foreign-tenant-tok"))
	if err != nil {
		t.Fatalf("IntrospectToken must not error on an inactive/foreign-tenant token, got %v", err)
	}
	if i.Active {
		t.Fatal("expected Active=false")
	}
	if i.Status() != TokenInactive {
		t.Fatalf("Status() = %v, want TokenInactive", i.Status())
	}
}

// TestTokenGrpcClient_UnauthenticatedRefreshRetry proves §9.3 for both
// operations: an UNAUTHENTICATED response drives the caller-supplied
// single-flight refresh exactly once, then retries the RPC once.
func TestTokenGrpcClient_UnauthenticatedRefreshRetry(t *testing.T) {
	conn := &scriptedConn{
		errs:    []error{status.Error(codes.Unauthenticated, "expired"), nil},
		replies: []proto.Message{nil, &axiamv1.ValidateTokenResponse{Valid: true}},
	}
	refreshed := 0
	client := NewTokenGrpcClient(conn, nil, func(context.Context) error {
		refreshed++
		return nil
	})

	v, err := client.ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !v.Valid {
		t.Fatal("expected the retried call's Valid:true to reach the caller")
	}
	if refreshed != 1 {
		t.Fatalf("expected exactly 1 refresh call, got %d", refreshed)
	}
	if conn.calls != 2 {
		t.Fatalf("expected exactly 2 RPCs (fail then retry), got %d", conn.calls)
	}
}

// recordingConn is a minimal fake grpclib.ClientConnInterface that hands
// the outgoing request message to record before replying, for tests that
// need to see what was SENT rather than only what came back.
type recordingConn struct {
	record func(proto.Message)
	reply  proto.Message
	calls  int
}

func (c *recordingConn) Invoke(_ context.Context, _ string, req, reply any, _ ...grpclib.CallOption) error {
	c.calls++
	if c.record != nil {
		if m, ok := req.(proto.Message); ok {
			c.record(m)
		}
	}
	if c.reply != nil {
		proto.Merge(reply.(proto.Message), c.reply)
	}
	return nil
}

func (c *recordingConn) NewStream(context.Context, *grpclib.StreamDesc, string, ...grpclib.CallOption) (grpclib.ClientStream, error) {
	return nil, errors.New("streaming not supported")
}

// TestTokenIntrospection_StatusAndVerifyPossession is TestTokenGrpcClient_
// TokenTypeDoesNotSayBoundness's counterpart on the TokenIntrospection
// side: all three Status() branches, plus VerifyPossession accepting an
// unbound result and refusing a bound one with no evidence.
func TestTokenIntrospection_StatusAndVerifyPossession(t *testing.T) {
	inactive := TokenIntrospection{Active: false}
	if got := inactive.Status(); got != TokenInactive {
		t.Fatalf("Status() = %v, want TokenInactive", got)
	}

	bearer := TokenIntrospection{Active: true, Cnf: nil}
	if got := bearer.Status(); got != TokenBearer {
		t.Fatalf("Status() = %v, want TokenBearer", got)
	}
	if err := bearer.VerifyPossession(axiam.PresentedProofs{}); err != nil {
		t.Fatalf("an unbound introspection must verify with no proofs, got %v", err)
	}

	bound := TokenIntrospection{Active: true, Cnf: &Confirmation{X5tS256: "thumb"}}
	if got := bound.Status(); got != TokenUnverifiable {
		t.Fatalf("Status() = %v, want TokenUnverifiable", got)
	}
	if err := bound.VerifyPossession(axiam.PresentedProofs{}); err == nil {
		t.Fatal("expected VerifyPossession to refuse a bound introspection with no evidence")
	}
	if err := bound.VerifyPossession(axiam.PresentedProofs{CertificateThumbprint: "thumb"}); err != nil {
		t.Fatalf("expected VerifyPossession to accept the matching certificate, got %v", err)
	}
}

// TestTokenGrpcClient_ValidateToken_NonUnauthenticatedErrorNeverEntersRefreshGuard
// proves the error-mapping path for a status code the §9 refresh guard does
// not apply to (rule: only UNAUTHENTICATED drives a refresh attempt).
func TestTokenGrpcClient_ValidateToken_NonUnauthenticatedErrorNeverEntersRefreshGuard(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.PermissionDenied, "denied")}}
	refreshed := 0
	client := NewTokenGrpcClient(conn, nil, func(context.Context) error {
		refreshed++
		return nil
	})

	_, err := client.ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := err.(*axiam.AuthzError); !ok {
		t.Fatalf("got %T, want *axiam.AuthzError", err)
	}
	if refreshed != 0 {
		t.Fatalf("PermissionDenied must never enter the refresh guard, got %d refresh call(s)", refreshed)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 RPC (no retry for a non-UNAUTHENTICATED error), got %d", conn.calls)
	}
}

// TestTokenGrpcClient_ValidateToken_RefreshErrorPropagatesWithoutRetry proves
// that when the caller-supplied refresh itself fails, that error reaches the
// caller directly and the RPC is not retried.
func TestTokenGrpcClient_ValidateToken_RefreshErrorPropagatesWithoutRetry(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
	refreshErr := errors.New("refresh failed")
	client := NewTokenGrpcClient(conn, nil, func(context.Context) error { return refreshErr })

	_, err := client.ValidateToken(context.Background(), axiam.Sensitive("tok"))
	if !errors.Is(err, refreshErr) {
		t.Fatalf("got %v, want the refresh error itself", err)
	}
	if conn.calls != 1 {
		t.Fatalf("a failed refresh must not be followed by a retry, got %d calls", conn.calls)
	}
}

// TestTokenGrpcClient_IntrospectToken_UnauthenticatedRefreshRetry is
// ValidateToken's TestTokenGrpcClient_UnauthenticatedRefreshRetry, mirrored
// for IntrospectToken.
func TestTokenGrpcClient_IntrospectToken_UnauthenticatedRefreshRetry(t *testing.T) {
	conn := &scriptedConn{
		errs:    []error{status.Error(codes.Unauthenticated, "expired"), nil},
		replies: []proto.Message{nil, &axiamv1.IntrospectTokenResponse{Active: true, Sub: "user-1"}},
	}
	refreshed := 0
	client := NewTokenGrpcClient(conn, nil, func(context.Context) error {
		refreshed++
		return nil
	})

	i, err := client.IntrospectToken(context.Background(), axiam.Sensitive("tok"))
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !i.Active || i.Sub != "user-1" {
		t.Fatalf("expected the retried call's response to reach the caller, got %+v", i)
	}
	if refreshed != 1 {
		t.Fatalf("expected exactly 1 refresh call, got %d", refreshed)
	}
	if conn.calls != 2 {
		t.Fatalf("expected exactly 2 RPCs (fail then retry), got %d", conn.calls)
	}
}

// TestTokenGrpcClient_IntrospectToken_RefreshErrorPropagatesWithoutRetry
// mirrors the ValidateToken case for IntrospectToken.
func TestTokenGrpcClient_IntrospectToken_RefreshErrorPropagatesWithoutRetry(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
	refreshErr := errors.New("refresh failed")
	client := NewTokenGrpcClient(conn, nil, func(context.Context) error { return refreshErr })

	_, err := client.IntrospectToken(context.Background(), axiam.Sensitive("tok"))
	if !errors.Is(err, refreshErr) {
		t.Fatalf("got %v, want the refresh error itself", err)
	}
	if conn.calls != 1 {
		t.Fatalf("a failed refresh must not be followed by a retry, got %d calls", conn.calls)
	}
}

// TestTokenGrpcClient_IntrospectToken_NoRefreshFuncMapsUnauthenticatedDirectly
// proves that with refresh == nil (a caller who never wired one), an
// UNAUTHENTICATED response maps straight to *axiam.AuthError with no retry
// attempt — the same nil-refresh posture AuthzClient/UserInfoClient already
// document.
func TestTokenGrpcClient_IntrospectToken_NoRefreshFuncMapsUnauthenticatedDirectly(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
	client := NewTokenGrpcClient(conn, nil, nil)

	_, err := client.IntrospectToken(context.Background(), axiam.Sensitive("tok"))
	if _, ok := err.(*axiam.AuthError); !ok {
		t.Fatalf("got %T, want *axiam.AuthError", err)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 RPC with no refresh func configured, got %d", conn.calls)
	}
}
