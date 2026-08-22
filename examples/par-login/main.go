// Command par-login shows Pushed Authorization Requests — CONTRACT.md §26
// (RFC 9126).
//
// PAR moves the authorization request off the browser. Instead of putting
// scope, redirect_uri, state and the PKCE challenge into a URL the user agent
// carries, the client POSTs them straight to AXIAM over an authenticated back
// channel and puts an opaque request_uri in the redirect. What travels through
// the browser is then a random string that cannot be edited into meaning
// something else.
//
// Required for a FAPI 2.0 client: profile: "fapi2" refuses a registration that
// does not set require_par, so such a client cannot authorize any other way.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

const (
	redirectURI = "https://app.example.com/auth/callback"
	scope       = "openid profile email"
)

func main() {
	client, err := axiam.NewClient(
		envOr("AXIAM_BASE_URL", "https://iam.example.com"),
		envOr("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"),
		axiam.WithOidcClientID(envOr("AXIAM_CLIENT_ID", "axiam-rp")),
		axiam.WithOidcClientSecret(os.Getenv("AXIAM_CLIENT_SECRET")),
	)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	if _, err := begin(context.Background(), client); err != nil {
		log.Printf("push: %v", err)
	}
}

// begin starts a login by pushing the request.
//
// OidcBegin still does the computing — §26.2 rule 1 forbids a second generator
// for state, nonce and PKCE, so OidcPar pushes what it produced rather than
// producing its own.
func begin(ctx context.Context, client *axiam.Client) (axiam.PushedAuthorizationRequest, error) {
	configuration, err := client.OidcDiscover(ctx)
	if err != nil {
		return axiam.PushedAuthorizationRequest{}, err
	}
	request, err := client.OidcBegin(configuration, axiam.OidcBeginParams{
		RedirectURI: redirectURI,
		Scope:       scope,
	})
	if err != nil {
		return axiam.PushedAuthorizationRequest{}, err
	}

	pushed, err := client.OidcPar(ctx, axiam.OidcParParams{
		Request:       request,
		RedirectURI:   redirectURI,
		Scope:         scope,
		Configuration: &configuration,
	})
	if err != nil {
		return axiam.PushedAuthorizationRequest{}, err
	}

	// Exactly two query parameters: client_id and request_uri. Not
	// response_type, not scope, not state — the server REFUSES a request
	// carrying both a request_uri and any inline authorization parameter
	// rather than merging them, because merging is where parameter confusion
	// lives (§26.2 rule 2). Do not "helpfully" re-add them.
	fmt.Printf("redirect the browser to %s\n", pushed.AuthorizationURL)

	// Store State, Nonce and CodeVerifier against the browser session, as you
	// would without PAR. RequestURI is single-use and short-lived; there is
	// nothing to retry with it if the redirect fails (§26.2 rule 3).
	return pushed, nil
}

// complete finishes the login. Unchanged by PAR — same grant, same verifier.
func complete(
	ctx context.Context,
	client *axiam.Client,
	pushed axiam.PushedAuthorizationRequest,
	code, returnedState string,
) error {
	if returnedState != pushed.State {
		return fmt.Errorf("state mismatch — abandon this login")
	}
	tokens, err := client.OidcExchange(ctx, axiam.OidcExchangeParams{
		Code:        code,
		RedirectURI: redirectURI,
		Nonce:       pushed.Nonce,
		// The verifier OidcBegin produced, carried through the push. One
		// value, so there is no second place for the two to disagree (rule 6).
		CodeVerifier: pushed.CodeVerifier,
	})
	if err != nil {
		return err
	}
	fmt.Printf("token set acquired, expires in %ds\n", tokens.ExpiresIn)
	return nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

var _ = complete
