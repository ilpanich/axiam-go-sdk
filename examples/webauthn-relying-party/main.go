// Command webauthn-relying-party shows WebAuthn / passkeys from Go —
// CONTRACT.md §24.
//
// Go has no authenticator, so this SDK ships the RELYING-PARTY half of a
// passkey ceremony: the four JSON round trips with AXIAM. That is not a
// consolation prize. A Go service completing a ceremony that ran on an Android
// or iOS handset is the relying party exactly as a browser is, and this is the
// shape that service takes:
//
//  1. Ask AXIAM for a challenge.
//  2. Hand the client the challenge in its platform JSON form (§24.6a) — the
//     exact string Android's CreatePublicKeyCredentialRequest and a browser's
//     parseCreationOptionsFromJSON() both take.
//  3. Take the client's response JSON back, unaltered, and post it to AXIAM.
//
// Nothing here emulates an authenticator. §24.6b rule 2 forbids it: a
// "credential" held in process memory is not a second factor.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	client, err := axiam.NewClient(
		envOr("AXIAM_BASE_URL", "https://iam.example.com"),
		envOr("AXIAM_TENANT_SLUG", "acme"),
		axiam.WithOrgSlug(envOr("AXIAM_ORG_SLUG", "globex")),
	)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	if err := signInWithAPasskey(context.Background(), client); err != nil {
		log.Printf("sign-in: %v", err)
	}
}

// signInWithAPasskey runs a usernameless ceremony from a service.
//
// The workspace still has to be named — a discoverable credential is resolved
// inside one tenant — but it comes from the client's own configuration, and
// this endpoint accepts slugs.
func signInWithAPasskey(ctx context.Context, client *axiam.Client) error {
	challenge, err := client.WebauthnDiscoverableStart(ctx, nil)
	if err != nil {
		return err
	}

	requestJSON, err := challenge.RequestJSON()
	if err != nil {
		return err
	}
	responseJSON, err := sendToDeviceAndAwaitReply(requestJSON)
	if err != nil {
		return err
	}

	session, err := client.WebauthnDiscoverableFinish(ctx, challenge.StateToken, responseJSON)
	if err != nil {
		return err
	}
	// The client is authenticated now — §24.3 rule 1 is not "MAY adopt".
	fmt.Printf("signed in, session %s, expires in %ds\n", session.SessionID, session.ExpiresIn)
	return nil
}

// enrolAPasskey enrols a credential for the signed-in user.
//
// The request JSON goes to the device untouched — every WebAuthn option is a
// security parameter the server chose, and a client that "helpfully" adjusts
// one has weakened a ceremony the server believes it configured (§24.0).
func enrolAPasskey(ctx context.Context, client *axiam.Client, name string) error {
	challenge, err := client.WebauthnRegisterStart(ctx)
	if err != nil {
		return err
	}
	requestJSON, err := challenge.RequestJSON()
	if err != nil {
		return err
	}
	responseJSON, err := sendToDeviceAndAwaitReply(requestJSON)
	if err != nil {
		return err
	}

	// The response goes back byte-for-byte: it is the input to a signature
	// check over bytes this process did not produce.
	credential, err := client.WebauthnRegisterFinish(ctx, challenge.StateToken, name, responseJSON)
	if err != nil {
		var authzErr *axiam.AuthzError
		if errors.As(err, &authzErr) {
			// §24.4 rule 1: the tenant's attestation policy refusing THIS
			// authenticator, and its message is the only way the person
			// holding the key learns a different one would work.
			return fmt.Errorf("attestation policy refused this device: %w", err)
		}
		return err
	}
	fmt.Printf("enrolled %s %q\n", credential.CredentialType, credential.Name)
	return nil
}

// signInWithPasswordThenPasskey uses a passkey as the second factor.
func signInWithPasswordThenPasskey(ctx context.Context, client *axiam.Client, email, password string) error {
	result, err := client.Login(ctx, email, password)
	if err != nil {
		return err
	}
	switch {
	case result.MFASetupRequired:
		// §25.2 rule 1 — see examples/account-lifecycle.
		fmt.Println("this tenant requires MFA and this account has none")
		return nil
	case !result.MFARequired:
		fmt.Println("signed in with the password alone")
		return nil
	}

	challenge, err := client.WebauthnAuthenticateStart(ctx, result.MFAToken)
	if err != nil {
		return err
	}
	requestJSON, err := challenge.RequestJSON()
	if err != nil {
		return err
	}
	responseJSON, err := sendToDeviceAndAwaitReply(requestJSON)
	if err != nil {
		return err
	}
	if _, err := client.WebauthnAuthenticateFinish(ctx, challenge.StateToken, responseJSON); err != nil {
		return err
	}
	fmt.Println("signed in with a passkey as the second factor")
	return nil
}

// reportADeviceFailure translates a failure the device reported into one
// vocabulary.
//
// Every platform reports a ceremony failure as one opaque type whose only
// machine-readable part is a name, so a device can relay just that. The five
// outcomes are the same everywhere, and already_registered is the one worth
// separating: the authenticator already holds a credential for this account and
// refused to mint a second, so the remedy is a different device rather than
// another attempt.
func reportADeviceFailure(errorNameFromDevice string) {
	failure := axiam.ClassifyWebauthnError(errorNameFromDevice)
	if failure == axiam.WebauthnAlreadyRegistered {
		fmt.Println("this device is already enrolled — try another")
	}
	fmt.Println(axiam.WebauthnErrorMessage(failure))
}

// sendToDeviceAndAwaitReply stands in for your own channel to the device.
//
// In a real deployment this is a websocket to a mobile app, a push
// notification, a QR-code handshake — whatever carries the string there and the
// answer back. Both directions are opaque to this process, which is the point.
func sendToDeviceAndAwaitReply(requestJSON string) (string, error) {
	_ = requestJSON
	return "", errors.New(
		"wire this to your own device channel; it must return the platform's " +
			"registrationResponseJson / authenticationResponseJson verbatim")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

var (
	_ = enrolAPasskey
	_ = signInWithPasswordThenPasskey
	_ = reportADeviceFailure
)
