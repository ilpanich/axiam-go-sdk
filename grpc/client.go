package grpc

import (
	"context"
	"fmt"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	axiam "github.com/ilpanich/axiam-go-sdk"
	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// NewGRPCClient constructs a *grpclib.ClientConn for target using creds and
// interceptor. It uses grpclib.NewClient (NOT the deprecated grpclib.Dial) —
// per grpc-go 1.63+, NewClient does not dial eagerly: connection errors
// (bad target, TLS handshake failure) surface on the first actual RPC call,
// not at construction time (RESEARCH.md Pitfall 5).
func NewGRPCClient(target string, creds credentials.TransportCredentials, interceptor grpclib.UnaryClientInterceptor) (*grpclib.ClientConn, error) {
	return grpclib.NewClient(target,
		grpclib.WithTransportCredentials(creds),
		grpclib.WithUnaryInterceptor(interceptor),
	)
}

// RefreshFunc performs the caller-owned single-flight refresh (§9) and
// returns once a fresh access token is cached. Supplied by the caller so
// this package never depends on the REST transport directly (RESEARCH.md
// D-05 / this plan's <action>).
type RefreshFunc func(ctx context.Context) error

// AuthzClient is a typed wrapper over the committed axiam.v1
// AuthorizationServiceClient stubs, exposing CheckAccess/BatchCheck
// (CONTRACT.md §1) with §2 gRPC status mapping and a single-flight-refresh
// retry on UNAUTHENTICATED.
type AuthzClient struct {
	inner   axiamv1.AuthorizationServiceClient
	refresh RefreshFunc
}

// NewAuthzClient wraps conn (built via NewGRPCClient, already carrying the
// auth/tenant interceptor) with the committed AuthorizationServiceClient
// stub. refresh drives the shared single-flight refresh (§9) on
// UNAUTHENTICATED; it may be nil, in which case UNAUTHENTICATED errors are
// returned immediately without a retry.
func NewAuthzClient(conn grpclib.ClientConnInterface, refresh RefreshFunc) *AuthzClient {
	return &AuthzClient{
		inner:   axiamv1.NewAuthorizationServiceClient(conn),
		refresh: refresh,
	}
}

// CheckAccessRequest is a single access check (CONTRACT.md §1), the gRPC
// analog of the REST authz-check request shape.
type CheckAccessRequest struct {
	TenantID   string
	SubjectID  string
	Action     string
	ResourceID string
	Scope      string
}

func (r CheckAccessRequest) toWire() *axiamv1.CheckAccessRequest {
	wire := &axiamv1.CheckAccessRequest{
		TenantId:   r.TenantID,
		SubjectId:  r.SubjectID,
		Action:     r.Action,
		ResourceId: r.ResourceID,
	}
	if r.Scope != "" {
		wire.Scope = &r.Scope
	}
	return wire
}

// CheckAccess evaluates a single authorization check (CONTRACT.md §1),
// returning (allowed, reason, error). On UNAUTHENTICATED, drives the
// caller-supplied single-flight refresh (§9) and retries exactly once —
// never a second time (§9.3).
//
// This tuple signature has no room for the §11 rule 9 reason_code; use
// CheckAccessDecision when you need to tell "no grant exists" apart from
// "a deny rule matched". Kept as-is so existing callers keep compiling.
func (c *AuthzClient) CheckAccess(ctx context.Context, req CheckAccessRequest) (bool, string, error) {
	decision, err := c.CheckAccessDecision(ctx, req)
	if err != nil {
		return false, "", err
	}
	return decision.Allowed, decision.Reason, nil
}

// CheckAccessDecision is CheckAccess returning the FULL decision, including
// the §11 rule 9 ReasonCode.
//
// It exists because CheckAccess's (bool, string, error) tuple predates that
// field and cannot carry it without a breaking signature change. The
// distinction it surfaces is not cosmetic: no_grant means "ask an admin for
// access", denied_by_rule means "an admin has already decided", and an
// application that cannot tell them apart sends users to raise tickets that
// will be refused.
//
// Same refresh-and-retry-once semantics as CheckAccess (§9, §9.3).
func (c *AuthzClient) CheckAccessDecision(ctx context.Context, req CheckAccessRequest) (CheckAccessResult, error) {
	wire := req.toWire()

	resp, err := c.inner.CheckAccess(ctx, wire)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return CheckAccessResult{}, refreshErr
			}
			resp, err = c.inner.CheckAccess(ctx, wire)
		}
		if err != nil {
			return CheckAccessResult{}, mapGRPCError(err)
		}
	}
	return mapCheckAccessResult(resp), nil
}

// BatchCheck evaluates an ordered list of checks; results are returned in
// the same order as reqs (CONTRACT.md §1). Shares the same
// UNAUTHENTICATED single-flight-retry behavior as CheckAccess.
func (c *AuthzClient) BatchCheck(ctx context.Context, reqs []CheckAccessRequest) ([]CheckAccessResult, error) {
	wire := make([]*axiamv1.CheckAccessRequest, len(reqs))
	for i, r := range reqs {
		wire[i] = r.toWire()
	}
	batchReq := &axiamv1.BatchCheckAccessRequest{Requests: wire}

	resp, err := c.inner.BatchCheckAccess(ctx, batchReq)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return nil, refreshErr
			}
			resp, err = c.inner.BatchCheckAccess(ctx, batchReq)
		}
		if err != nil {
			return nil, mapGRPCError(err)
		}
	}

	results := make([]CheckAccessResult, len(resp.GetResults()))
	for i, r := range resp.GetResults() {
		results[i] = mapCheckAccessResult(r)
	}
	return results, nil
}

// CheckAccessResult is a single result within a BatchCheck response.
type CheckAccessResult struct {
	// Allowed reports whether the checked action is permitted.
	//
	// THIS FIELD ALONE CARRIES THE OUTCOME. ReasonCode explains it and never
	// contradicts it.
	Allowed bool
	// Reason is the server's human-readable explanation, when it sent one —
	// the SINGLE public reason accessor CONTRACT.md §11.2 rule 9 (SDK-Q10,
	// contract 1.19) requires. See mapCheckAccessResult for how it is
	// derived from the wire response's `reason` (field 4) and deprecated
	// `deny_reason` (field 2).
	//
	// This field replaces what was, before SDK-Q10, named DenyReason: the
	// gRPC decision and the REST decision are now one reconciled shape
	// (`allowed` + `reason_code` + `reason`), so the gRPC-only name is
	// retired rather than kept alongside a second accessor. There is no
	// released tag of this module yet, so this is not a breaking change to
	// any shipped API.
	Reason string
	// ReasonCode is the B1 deny-override decision reason (CONTRACT.md §11
	// rule 9): "allowed", "no_grant" or "denied_by_rule".
	//
	// proto3 renders an unset string as "", so an older server that never set
	// field 3 is indistinguishable from one that set it empty — both mean "no
	// reason code", and both arrive here as "".
	ReasonCode string
}

// mapCheckAccessResult maps a wire CheckAccessResponse to the public
// CheckAccessResult, applying CONTRACT.md §11.2 rule 9's SDK-Q10 (contract
// 1.19) reconciliation of the gRPC and REST decision shapes.
//
// Read `reason` (proto field 4, explicit presence via a *string) when the
// server sent it — including an explicitly-empty string, which is NOT a
// reason and must not trigger the fallback below. Fall back to the
// deprecated `deny_reason` (field 2) only when `reason` is absent AND the
// decision is a refusal: that combination means the server predates
// SDK-Q10 (a pre-1.19 server never sets field 4 at all), and is the one
// case where the identical string genuinely lives only in the old field.
// `reason` absent on an ALLOW is not that case — an allow has nothing to
// say either way — so no fallback happens there, even if a response
// carries a stray `deny_reason` on an allow.
//
// Exactly one reason surfaces to callers, via CheckAccessResult.Reason;
// `deny_reason` is never exposed on the public type (see its doc comment).
func mapCheckAccessResult(resp *axiamv1.CheckAccessResponse) CheckAccessResult {
	reason := ""
	switch {
	case resp.Reason != nil:
		// Explicit presence: whatever the server sent — including "" — is
		// authoritative and is not replaced by the legacy field.
		reason = *resp.Reason
	case !resp.GetAllowed():
		// `reason` absent on a refusal only: a pre-SDK-Q10 server, which
		// never populated field 4 and carries the identical string in
		// `deny_reason` instead.
		reason = resp.GetDenyReason() //nolint:staticcheck // SA1019: the one sanctioned read site for the deprecated fallback field, until AXIAM 2.0 removes it.
	}
	return CheckAccessResult{
		Allowed:    resp.GetAllowed(),
		Reason:     reason,
		ReasonCode: resp.GetReasonCode(),
	}
}

// mapGRPCError maps a terminal gRPC error to the CONTRACT.md §2 error
// taxonomy (AuthError/AuthzError/NetworkError) via the shared status-code
// table:
//
//	UNAUTHENTICATED (16)    -> AuthError
//	PERMISSION_DENIED (7)   -> AuthzError
//	UNAVAILABLE (14)        -> NetworkError
//	DEADLINE_EXCEEDED (4)   -> NetworkError
//	INTERNAL (13)           -> NetworkError
//	RESOURCE_EXHAUSTED (8)  -> NetworkError
//	other                   -> NetworkError
func mapGRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return &axiam.NetworkError{Message: fmt.Sprintf("grpc: %v", err)}
	}
	switch st.Code() {
	case codes.Unauthenticated:
		return &axiam.AuthError{Message: st.Message()}
	case codes.PermissionDenied:
		return &axiam.AuthzError{Message: st.Message()}
	default:
		return &axiam.NetworkError{Message: fmt.Sprintf("grpc status %s: %s", st.Code(), st.Message())}
	}
}
