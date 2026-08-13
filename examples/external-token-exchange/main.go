// External-IdP token exchange (CONTRACT.md §15.7) — accepting a partner's
// token at an API gateway.
//
// The situation: a partner runs their own IdP (Entra, Okta, Keycloak). Their
// service calls yours carrying THEIR token, which means nothing to your
// services. You present it here and get back an AXIAM token scoped to what the
// resolved AXIAM user may actually do.
//
// This is the same TokenExchange as ./examples/token-exchange — §15.7 adds no
// new operation. What differs is what you pass and what the refusals mean:
//
//   - SubjectTokenType is named explicitly (…:jwt), because only you know what
//     kind of token you are holding.
//   - There is no actor token. Delegation across a trust boundary needs a
//     second trust decision that v1 does not make.
//   - One refusal means "fix the AXIAM trust configuration" and every other
//     one means "fix your token".
//
// The partner's token is EVIDENCE OF AUTHENTICATION, never a grant of
// authorization: their IdP stays the authority on who authenticated, AXIAM
// stays the authority on what they may do here. Nothing in the partner's token
// can widen the result.
//
// Run: go run ./examples/external-token-exchange
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// The one normative error_description (§15.7). It is the ONLY external failure
// given a distinguishable message, and matching on it is explicitly allowed.
const issuerNotConfigured = "the subject token's issuer is not configured for token exchange"

func main() {
	baseURL := envOr("AXIAM_BASE_URL", "https://localhost:8443")
	tenantID := envOr("AXIAM_TENANT_ID", "11111111-2222-3333-4444-555555555555")
	clientID := envOr("AXIAM_OIDC_CLIENT_ID", "api-gateway")
	clientSecret := envOr("AXIAM_OIDC_CLIENT_SECRET", "gateway-secret")

	// The partner's token, as it would arrive on an inbound request — from an
	// Authorization header your gateway is about to stop trusting blindly.
	partnerToken := envOr("PARTNER_SUBJECT_TOKEN", "the-partners-access-token")

	// The exchanging client is a confidential service and authenticates. It
	// does NOT need the may_impersonate grant: the evidence here is a trusted
	// IdP's signed assertion that the user authenticated, not this client's
	// own say-so that it may be them.
	client, err := axiam.NewClient(baseURL, "acme",
		axiam.WithOidcClientID(clientID),
		axiam.WithOidcClientSecret(clientSecret),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	exchanged, err := client.TokenExchange(context.Background(), axiam.TokenExchangeParams{
		SubjectToken: axiam.Sensitive(partnerToken),

		// Named, not guessed. The SDK never decodes the subject token to pick
		// this (§15.7) — a wrong value is the difference between a request
		// that is refused and one that is silently reinterpreted, so it is
		// yours to state. AXIAM accepts …:jwt or …:access_token for an
		// external issuer, and refuses refresh and ID token types by name.
		SubjectTokenType: axiam.SubjectTokenTypeJWT,

		// NO ActorToken. Delegation across a trust boundary is unsupported in
		// v1 and sending one is invalid_request — not something to work around
		// by dropping it and re-sending, which would turn the delegation you
		// asked for into an impersonation you did not.

		// Omitting Scopes asks for everything the trust configuration and the
		// user's own permissions allow. Naming scopes gets you told about any
		// you cannot have, which is usually what you want at a gateway.
		Scopes:   []string{"read:orders"},
		Audience: "https://orders.internal",
		TenantID: tenantID,
	})
	if err != nil {
		explainAndExit(err)
	}

	// Read what you actually got. The granted scope is the intersection of
	// four gates — your request, the provider's scope map, this client's
	// registration, and the RBAC engine at mint time — so it may be narrower
	// than you asked for even on success (§15.2 rule 7).
	scope := exchanged.Scope
	if scope == "" {
		scope = "(server default)"
	}
	fmt.Printf("exchanged for %ds, granted scope: %s\n", exchanged.ExpiresIn, scope)
	// §15.2 rule 6: surfaced so a client that asked for one type and received
	// another can tell.
	fmt.Printf("issued token type: %s\n", exchanged.IssuedTokenType)

	// Hand it onward in ONE outbound call, exactly as in the same-domain case.
	// It is not this gateway's session (rule 5) and there is no refresh token
	// (rule 4) — re-run the exchange.
	//
	// The issued token carries an `ext_exchange` claim naming the partner
	// issuer, which a resource server MAY read to tell a cross-domain token
	// from a locally-issued one. Forward the token as-is: never strip the
	// claim, and never treat its presence or absence as an authorization
	// input of your own — the scope claim and the server's checks remain the
	// authority (§15.7).
	//
	// Do not feed this token back into another exchange either. Exchanges do
	// not compose: both paths refuse a subject token carrying `ext_exchange`,
	// because otherwise trust composes silently — A trusts B, B trusts C,
	// therefore A trusts C, which nobody configured.
	_ = "Bearer " + string(exchanged.AccessToken)
}

// explainAndExit turns a refusal into the one thing that matters: whose
// problem it is.
func explainAndExit(err error) {
	var protocolErr *axiam.OAuthProtocolError
	if !errors.As(err, &protocolErr) {
		// Not a protocol refusal — a transport or configuration failure.
		log.Fatalf("TokenExchange: %v", err)
	}

	switch protocolErr.ErrorCode {
	case "invalid_grant":
		// The single distinguishable external failure. Everything else on
		// invalid_grant — bad signature, expired, too old, audience not
		// accepted, wrong token kind, subject not linked — answers with a
		// generic description on purpose: which of a dozen checks refused a
		// token is a map of the server's validation order, drawn one request
		// at a time.
		if strings.Contains(protocolErr.ErrorDescription, issuerNotConfigured) {
			log.Fatal("FIX THE AXIAM TRUST CONFIG: an operator must enable token " +
				"exchange for this federation provider and list your audience in " +
				"accepted_audiences. Your token is not the problem.")
		}
		log.Fatal("FIX YOUR TOKEN: the subject token was refused. Check that it is " +
			"current, addressed to the audience AXIAM accepts, and that its subject " +
			"is linked to an AXIAM user. The precise reason is in the AXIAM audit log.")

	case "invalid_request":
		// Sending an actor token, naming a refresh or ID token type, or
		// presenting a token that is itself the product of an exchange. None
		// of these is retryable as a different type or a rewritten request.
		log.Fatalf("The request is not one AXIAM will accept, as written: %s",
			protocolErr.ErrorDescription)

	case "invalid_scope":
		// Do NOT re-send with fewer scopes. The server refused rather than
		// silently narrowing precisely so you would find out here. Either the
		// provider's scope_map does not map onto the scope you named, or the
		// resolved user does not hold it in AXIAM's own RBAC.
		log.Fatalf("A requested scope is not available to this user: %s",
			protocolErr.ErrorDescription)

	case "invalid_target":
		log.Fatalf("The audience/resource is not registered to this client: %s",
			protocolErr.ErrorDescription)

	case "unauthorized_client":
		log.Fatal("This client is not registered for the token-exchange grant — " +
			"a registration fact an operator must fix.")
	}

	log.Fatalf("TokenExchange: %v", err)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
