package grpc

import (
	"context"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	axiam "github.com/ilpanich/axiam-go-sdk"
	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// TokenGrpcClient is a typed wrapper over the committed axiam.v1
// TokenServiceClient stub, exposing ValidateToken/IntrospectToken
// (CONTRACT.md §1.1.1, §10.3, contract 1.51) with §2 gRPC status mapping and
// a single-flight-refresh retry on UNAUTHENTICATED — built like
// AuthzClient/UserInfoClient on the SAME shared channel and interceptor.
//
// This is the operation §1.1.1 exists to specify: an SDK validating or
// introspecting a token over gRPC needs a public method that returns what
// §10.3 obliges it to read, and until contract 1.51 no method in §1's closed
// list could return cnf at all.
type TokenGrpcClient struct {
	inner    axiamv1.TokenServiceClient
	hasToken func() bool
	refresh  RefreshFunc
}

// NewTokenGrpcClient wraps conn (built via NewGRPCClient, already carrying
// the same auth/tenant interceptor as AuthzClient/UserInfoClient) with the
// committed TokenServiceClient stub.
//
// hasToken reports whether the caller currently holds a bearer token — e.g.
// backed by internal/refreshguard.Guard.CachedAccessToken's second return
// value. §1.1.1 rule 2 requires both operations to refuse client-side, with
// ZERO wire calls, when the caller holds none: the CALLER's token
// authenticates the RPC through the shared interceptor exactly as it does
// for CheckAccess/GetUserInfo, and the interceptor's own UNAUTHENTICATED
// path would instead route straight into the refresh guard with nothing to
// refresh. hasToken may be nil, in which case this precondition is not
// checked locally and an absent token is left to the server's own
// UNAUTHENTICATED (mapped to *axiam.AuthError as usual) — the same
// posture AuthzClient/UserInfoClient already have, so a caller upgrading an
// existing wiring loses nothing by not supplying it.
//
// refresh drives the shared single-flight refresh (§9) on UNAUTHENTICATED;
// it may be nil, in which case UNAUTHENTICATED errors are returned
// immediately without a retry.
func NewTokenGrpcClient(conn grpclib.ClientConnInterface, hasToken func() bool, refresh RefreshFunc) *TokenGrpcClient {
	return &TokenGrpcClient{
		inner:    axiamv1.NewTokenServiceClient(conn),
		hasToken: hasToken,
		refresh:  refresh,
	}
}

// Confirmation is CONTRACT.md §10.1 rule 9's "cnf" claim, as carried by a
// TokenService response (§10.3): CnfClaim { x5t_s256, jkt }. A nil pointer
// means the claim was ABSENT — the token is unbound. A non-nil value with
// both fields empty is the wire-level spelling of an empty {} object
// (§10.3 rule 3): proto3 cannot distinguish "absent string" from "empty
// string", so a *Confirmation is never constructed non-nil unless the
// server actually sent a cnf message, and Confirmation.Verify treats a
// present-but-empty value as "names nothing checkable" and refuses it —
// never as unbound.
type Confirmation = axiam.Confirmation

// TokenStatus is what a validated/introspected token's confirmation says
// about whether it is safe to treat as usable BY WHOEVER PRESENTED IT
// (CONTRACT.md §10.3 rule 2 / §1.1.1 rule 4). valid/active alone answers
// "signature, expiry and tenant check out" — never "the caller may
// proceed".
type TokenStatus int

const (
	// TokenInactive is an invalid/inactive token (Valid/Active was false).
	// Every other field on the result is a server-reported zero value and
	// MUST NOT be trusted.
	TokenInactive TokenStatus = iota
	// TokenBearer is a valid, UNBOUND token: cnf was absent. Usable by
	// whoever presented it, subject to §10.1 rules 1-8.
	TokenBearer
	// TokenSenderConstrained is a valid, BOUND token whose binding this
	// caller has VERIFIED against its own connection (VerifyPossession
	// returned nil). Usable by the party that verification confirmed, and
	// by no one else.
	TokenSenderConstrained
	// TokenUnverifiable is a valid, BOUND token this caller has NOT (yet)
	// verified possession of — either VerifyPossession was never called, or
	// it returned an error. MUST NOT be treated as usable.
	TokenUnverifiable
)

// TokenValidation is ValidateToken's typed result — CONTRACT.md §1.1.1 rule
// 3's full field set for `validate_token`. Every response field is modeled;
// none is dropped on the grounds that a caller did not ask for it.
type TokenValidation struct {
	// Valid alone carries the server's yes/no. See Status/VerifyPossession
	// for whether the token is USABLE by whoever presented it — §1.1.1
	// rule 4: "valid ... is not usable as presented".
	Valid     bool
	SubjectID string
	TenantID  string
	OrgID     string
	// Exp is the token's expiry (Unix seconds). Zero when Valid is false.
	Exp int64
	// Cnf is nil for an unbound token, or for ANY token when Valid is
	// false (§10.3 rule 6: a token from another tenant is valid:false with
	// every other field empty and no cnf — an answer, not an error).
	Cnf *Confirmation
	// TokenType is "Bearer" or "DPoP" (RFC 9449 §5) — and does NOT say
	// whether the token is bound (§1.1.1 rule 5): a certificate-bound
	// device token (§6.1) is reported "Bearer". Decide boundness from Cnf
	// alone.
	TokenType string
}

// Status classifies this validation per §10.3 rule 2 / §1.1.1 rule 4,
// WITHOUT verifying possession — call VerifyPossession first if Cnf is
// non-nil and you need TokenSenderConstrained rather than
// TokenUnverifiable.
func (v TokenValidation) Status() TokenStatus {
	if !v.Valid {
		return TokenInactive
	}
	if v.Cnf == nil {
		return TokenBearer
	}
	return TokenUnverifiable
}

// VerifyPossession applies CONTRACT.md §10.1 rule 9 to this validation's Cnf
// against proofs taken from THIS caller's OWN connection — never from the
// inspected token's presenter, which is a different party the AXIAM server
// cannot itself check (§10.3 rule 2: "the SDK MUST additionally verify
// possession against its own connection"). Returns nil (accept) for an
// unbound token with any proofs, including none. Returns a jwks
// sentinel error (axiam.ErrNoClientCertificate,
// axiam.ErrCertificateBindingMismatch, axiam.ErrNoDPoPProof,
// axiam.ErrDPoPBindingMismatch, axiam.ErrUnverifiableConfirmation) when
// bound and the proofs do not satisfy the binding — including a
// present-but-empty Cnf (§10.3 rule 3), which is unverifiable rather than
// unbound.
func (v TokenValidation) VerifyPossession(proofs axiam.PresentedProofs) error {
	return v.Cnf.Verify(proofs)
}

// TokenIntrospection is IntrospectToken's typed result — CONTRACT.md
// §1.1.1 rule 3's RFC 7662 field set, extended with cnf, permissions and
// ext_exchange_iss.
type TokenIntrospection struct {
	Active         bool
	Sub            string
	TenantID       string
	OrgID          string
	Iss            string
	Iat            int64
	Exp            int64
	Jti            string
	Scope          string
	ClientID       string
	TokenType      string
	Cnf            *Confirmation
	Permissions    []RptPermission
	ExtExchangeIss string
}

// Status mirrors TokenValidation.Status, reading Active in place of Valid.
func (i TokenIntrospection) Status() TokenStatus {
	if !i.Active {
		return TokenInactive
	}
	if i.Cnf == nil {
		return TokenBearer
	}
	return TokenUnverifiable
}

// VerifyPossession mirrors TokenValidation.VerifyPossession.
func (i TokenIntrospection) VerifyPossession(proofs axiam.PresentedProofs) error {
	return i.Cnf.Verify(proofs)
}

// RptPermission is one UMA 2.0 RPT permission entry (§20), as introspection
// reports it.
type RptPermission struct {
	ResourceID     string
	ResourceScopes []string
	Exp            int64
}

// ValidateToken invokes axiam.v1.TokenService/ValidateToken to inspect
// accessToken — a DIFFERENT credential from the caller's own bearer token,
// which authenticates the RPC itself through the shared interceptor exactly
// as it does for CheckAccess/GetUserInfo (§1.1.1 rule 1). accessToken is
// Sensitive(§7) and has NO default: it can never silently fall back to the
// caller's own token.
//
// With no caller token (hasToken supplied and reporting false), fails
// client-side with *axiam.AuthError and makes ZERO wire calls (rule 2). On
// UNAUTHENTICATED, drives the caller-supplied single-flight refresh (§9)
// and retries exactly once — never a second time (§9.3), exactly like
// CheckAccess/GetUserInfo.
func (c *TokenGrpcClient) ValidateToken(ctx context.Context, accessToken axiam.Sensitive) (TokenValidation, error) {
	if c.hasToken != nil && !c.hasToken() {
		return TokenValidation{}, &axiam.AuthError{Message: "ValidateToken: no caller token — log in before calling ValidateToken (CONTRACT.md §1.1.1 rule 2)"}
	}

	req := &axiamv1.ValidateTokenRequest{AccessToken: accessToken.Expose()}

	resp, err := c.inner.ValidateToken(ctx, req)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return TokenValidation{}, refreshErr
			}
			resp, err = c.inner.ValidateToken(ctx, req)
		}
		if err != nil {
			return TokenValidation{}, mapGRPCError(err)
		}
	}
	return tokenValidationFromWire(resp), nil
}

// IntrospectToken invokes axiam.v1.TokenService/IntrospectToken. See
// ValidateToken for the caller-token-vs-inspected-token distinction (rule
// 1), the rule-2 precondition, and the refresh-and-retry-once behaviour —
// identical here.
func (c *TokenGrpcClient) IntrospectToken(ctx context.Context, accessToken axiam.Sensitive) (TokenIntrospection, error) {
	if c.hasToken != nil && !c.hasToken() {
		return TokenIntrospection{}, &axiam.AuthError{Message: "IntrospectToken: no caller token — log in before calling IntrospectToken (CONTRACT.md §1.1.1 rule 2)"}
	}

	req := &axiamv1.IntrospectTokenRequest{AccessToken: accessToken.Expose()}

	resp, err := c.inner.IntrospectToken(ctx, req)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return TokenIntrospection{}, refreshErr
			}
			resp, err = c.inner.IntrospectToken(ctx, req)
		}
		if err != nil {
			return TokenIntrospection{}, mapGRPCError(err)
		}
	}
	return tokenIntrospectionFromWire(resp), nil
}

// cnfFromWire maps a wire CnfClaim to *Confirmation. §10.3 rule 3: proto3
// cannot distinguish "absent" from "present but empty", so a non-nil wire
// message is ALWAYS carried through as a non-nil *Confirmation, even when
// both fields are empty — Confirmation.Verify (via NamesNothingCheckable)
// is what turns that into a refusal rather than a false "unbound" reading.
func cnfFromWire(w *axiamv1.CnfClaim) *Confirmation {
	if w == nil {
		return nil
	}
	return &Confirmation{X5tS256: w.GetX5TS256(), Jkt: w.GetJkt()}
}

func tokenValidationFromWire(resp *axiamv1.ValidateTokenResponse) TokenValidation {
	return TokenValidation{
		Valid:     resp.GetValid(),
		SubjectID: resp.GetSubjectId(),
		TenantID:  resp.GetTenantId(),
		OrgID:     resp.GetOrgId(),
		Exp:       resp.GetExp(),
		Cnf:       cnfFromWire(resp.GetCnf()),
		TokenType: resp.GetTokenType(),
	}
}

func tokenIntrospectionFromWire(resp *axiamv1.IntrospectTokenResponse) TokenIntrospection {
	permissions := make([]RptPermission, 0, len(resp.GetPermissions()))
	for _, p := range resp.GetPermissions() {
		permissions = append(permissions, RptPermission{
			ResourceID:     p.GetResourceId(),
			ResourceScopes: p.GetResourceScopes(),
			Exp:            p.GetExp(),
		})
	}
	return TokenIntrospection{
		Active:         resp.GetActive(),
		Sub:            resp.GetSub(),
		TenantID:       resp.GetTenantId(),
		OrgID:          resp.GetOrgId(),
		Iss:            resp.GetIss(),
		Iat:            resp.GetIat(),
		Exp:            resp.GetExp(),
		Jti:            resp.GetJti(),
		Scope:          resp.GetScope(),
		ClientID:       resp.GetClientId(),
		TokenType:      resp.GetTokenType(),
		Cnf:            cnfFromWire(resp.GetCnf()),
		Permissions:    permissions,
		ExtExchangeIss: resp.GetExtExchangeIss(),
	}
}
