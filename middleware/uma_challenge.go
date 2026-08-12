package middleware

// This file adds the emit half of CONTRACT.md §20.3 to the §11 RequireAccess
// guard: with a UmaChallenger configured, a denial stops being a bare 403 and
// carries a fresh permission ticket in `WWW-Authenticate: UMA`, so a UMA-aware
// client knows where to go for authority instead of only being told "no".

import (
	"context"
	"log/slog"
	"net/http"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// UmaTicketMinter is the minimal interface a UmaChallenger needs to mint a
// permission ticket — satisfied by *axiam.Client's UmaRequestTicket. Kept as
// an interface for the same reason AccessChecker is one: tests substitute a
// fake without a live AXIAM server, and this package does not hard-depend on
// the client's full concrete surface.
type UmaTicketMinter interface {
	UmaRequestTicket(ctx context.Context, pat axiam.Sensitive, permissions []axiam.RequestedPermission) (axiam.Sensitive, error)
}

// UmaChallenger is a configured `WWW-Authenticate: UMA` emitter (§20.3, emit
// half). Pass one to RequireAccess via WithUmaChallenge.
//
// OPT-IN, AND DELIBERATELY SO. Emitting a challenge means minting a
// credential — a wire call to the Protection API, and a live ticket, produced
// on a path the caller did not explicitly request. A guard that did that on
// every denial by default would turn each unauthorized request into a
// Protection API call, which is a denial-of-service amplifier pointed at your
// own authorization server. So it happens only where an application asked for
// it.
//
// FAILURE IS NOT ESCALATION. If minting fails — the PAT expired, the
// Protection API is down, the resource declares none of the requested scopes —
// the denial still surfaces as an ordinary 403 without a challenge. A caller
// who was going to be refused is refused either way; letting a Protection API
// outage turn a deny into a 503 would hand the outage a second consequence,
// and letting it turn into an allow would be a security bug.
type UmaChallenger struct {
	// Realm is the protection realm named in the header.
	Realm string
	// ASURI is the authorization server the caller should redeem the ticket
	// at — normally this deployment's issuer, read from discovery rather than
	// concatenated by hand (§12.3 rule 6).
	ASURI string
	// PAT is a Protection API Token: a client-credentials token carrying the
	// `uma_protection` scope (§20.2 rule 1). A user token cannot stand in — a
	// minted ticket is bound to the client_id that minted it.
	PAT axiam.Sensitive
	// Minter reaches the Protection API. Normally the *axiam.Client itself.
	Minter UmaTicketMinter
}

// WithUmaChallenge makes RequireAccess answer a denial with a
// `WWW-Authenticate: UMA` challenge carrying a freshly minted ticket for the
// action that was refused (§20.3).
//
// A nil challenger is ignored, leaving the plain §11 behavior — so a caller
// that builds one conditionally does not have to branch at the call site.
func WithUmaChallenge(challenger *UmaChallenger) RequireOption {
	return func(c *requireConfig) { c.challenger = challenger }
}

// umaChallengeHeader mints one ticket for the pair that was just refused and
// formats the challenge, reporting ok=false when that fails.
//
// The requested scope is the AXIAM *action* (§20.2): asking for anything else
// would offer the caller authority other than the one they were denied, and
// would step outside the grants the engine just evaluated — deny rules
// included.
func umaChallengeHeader(ctx context.Context, challenger *UmaChallenger, logger *slog.Logger, action, resourceID string) (string, bool) {
	ticket, err := challenger.Minter.UmaRequestTicket(ctx, challenger.PAT, []axiam.RequestedPermission{{
		ResourceID:     resourceID,
		ResourceScopes: []string{action},
	}})
	if err != nil {
		// Swallowed deliberately — see the type's doc comment. The denial
		// stands on its own; only the sugar is lost.
		logAuthzOutcome(logger, action, resourceID, "uma ticket minting failed; denying without a challenge")
		return "", false
	}
	return axiam.UmaChallengeHeader(challenger.Realm, challenger.ASURI, ticket), true
}

// setUmaChallenge sets the response's WWW-Authenticate header when a
// challenger is configured and minting succeeds. Called on the deny path only:
// an allow mints nothing.
func setUmaChallenge(w http.ResponseWriter, r *http.Request, cfg *requireConfig, action, resourceID string) {
	if cfg.challenger == nil {
		return
	}
	if header, ok := umaChallengeHeader(r.Context(), cfg.challenger, cfg.logger, action, resourceID); ok {
		w.Header().Set("WWW-Authenticate", header)
	}
}
