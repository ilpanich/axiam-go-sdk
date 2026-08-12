// Command uma-client is the client half of the UMA 2.0 (CONTRACT.md §20)
// example pair. Run examples/uma-resource-server first; this program talks to
// it.
//
// The flow, which is the whole reason UMA exists:
//
//  1. Ask for the invoice with the user's ordinary token. The resource server
//     refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket
//     and an authorization server.
//  2. Parse the challenge. Note what happens next, and what does not: parsing
//     performs no exchange (§20.3). The as_uri in that header is a host the
//     *server we just failed against* chose; auto-redeeming would send the
//     user's token wherever a 403 pointed.
//  3. Decide to trust it, then exchange the ticket for an RPT.
//  4. Retry with the RPT.
//
// Step 3 is a decision, not a formality — this example makes it explicitly, by
// comparing the nominated as_uri against the issuer this client already
// trusts, and refusing when they differ.
//
// Run: go run ./examples/uma-client
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	ctx := context.Background()
	resourceServer := getenv("AXIAM_RESOURCE_SERVER", "http://127.0.0.1:8081")
	// The resource server printed this id when it registered.
	invoiceID := getenv("AXIAM_INVOICE_ID", "00000000-0000-0000-0000-000000000000")
	// The requesting party's own token — what this program would normally send
	// and, in step 3, the claim_token that names *who* is asking.
	userToken := getenv("AXIAM_USER_TOKEN", "the-requesting-partys-access-token")

	// The exchange is a token-endpoint grant, so this client is confidential.
	client, err := axiam.NewClient(
		getenv("AXIAM_BASE_URL", "https://localhost:8443"),
		getenv("AXIAM_TENANT_SLUG", "acme"),
		axiam.WithOidcClientID(getenv("AXIAM_OIDC_CLIENT_ID", "invoices-client")),
		axiam.WithOidcClientSecret(getenv("AXIAM_OIDC_CLIENT_SECRET", "client-secret")))
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	url := resourceServer + "/invoices/" + invoiceID

	// ---- 1. The refusal ----
	refused, err := get(ctx, url, userToken)
	if err != nil {
		log.Fatalf("first attempt failed: %v", err)
	}
	defer func() { _ = refused.Body.Close() }()
	fmt.Printf("first attempt: %d\n", refused.StatusCode)

	header := refused.Header.Get("WWW-Authenticate")
	if header == "" {
		// A resource server that refuses without a challenge is telling you it
		// has nothing to offer — there is no ticket to redeem, and retrying the
		// same request would be pointless.
		fmt.Println("no WWW-Authenticate header: this refusal is not actionable.")
		return
	}

	// ---- 2. Parse, and only parse ----
	challenge, ok := axiam.UmaParseChallenge(header)
	if !ok || challenge.Ticket == "" {
		fmt.Println("the challenge names no ticket; nothing to redeem.")
		return
	}

	// Nothing from the challenge is echoed, and there are two separate reasons
	// for that.
	//
	// The ticket, because §20.6 says so: its 60-second life does not make it
	// harmless — for those 60 seconds it IS the credential that converts into
	// an RPT, so a header in a log line is a live credential in a log line.
	//
	// The realm and as_uri, because they are strings a *remote* server chose.
	// They are not secrets, but echoing attacker-controlled text into a
	// terminal or a log file is its own small hazard (escape sequences, log
	// forging), and an example is the last place to teach the habit. What
	// matters here is the shape of the challenge, not its contents.
	fmt.Printf("challenge parsed: as_uri present=%t, ticket present=true\n", challenge.AsURI != "")

	// ---- 3. The trust decision ----
	//
	// This is the step §20.3 exists to keep in the caller's hands. The SDK
	// parsed the header and stopped; deciding whether to send the user's token
	// to the host it names is this program's call, and it is a real one — a
	// compromised or merely misconfigured resource server could nominate
	// anything here.
	configuration, err := client.OidcDiscover(ctx)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}
	if challenge.AsURI != "" && trimSlash(challenge.AsURI) != trimSlash(configuration.Issuer) {
		// Neither side of the comparison is echoed. The nominated value for the
		// reasons above; our own issuer because it is reached through a client
		// constructed with a client secret, and an example that prints values
		// derived from that object is teaching a habit that is fine here and
		// wrong three refactors later. The decision and its outcome are what a
		// reader needs; the values are two lines away in a debugger.
		fmt.Println("refusing to redeem: the challenge nominates an authorization server")
		fmt.Println("that is not the issuer this client already trusts.")
		fmt.Println("this is the auto-exchange §20.3 forbids, and why it forbids it.")
		return
	}
	fmt.Println("as_uri matches the issuer we already trust; redeeming.")

	// ---- 4. Exchange, then retry ----
	//
	// One request. A ticket is spent whether or not this succeeds (§20.2 rule
	// 6), so on failure the next step is a *new* ticket — which means going
	// back to step 1, not resending this one.
	rpt, err := client.UmaExchangeTicket(ctx, axiam.UmaExchangeTicketParams{
		Ticket:        challenge.Ticket,
		ClaimToken:    axiam.Sensitive(userToken),
		Configuration: &configuration,
	})
	if err != nil {
		fmt.Println("exchange failed; the ticket is spent either way —")
		fmt.Println("request a new one by retrying the call from step 1.")
		return
	}
	fmt.Printf("got an RPT, valid for %ds\n", rpt.ExpiresIn)

	allowed, err := get(ctx, url, string(rpt.AccessToken))
	if err != nil {
		log.Fatalf("second attempt failed: %v", err)
	}
	defer func() { _ = allowed.Body.Close() }()
	fmt.Printf("second attempt: %d\n", allowed.StatusCode)
	if allowed.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(allowed.Body)
		fmt.Printf("body: %s", body)
	}
}

// get issues a bearer-authenticated GET against the resource server. Plain
// net/http rather than the SDK client: the resource server is this program's
// own peer, not the AXIAM deployment.
func get(ctx context.Context, url, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func trimSlash(value string) string {
	return strings.TrimSuffix(value, "/")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
