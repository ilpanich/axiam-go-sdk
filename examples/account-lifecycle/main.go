// Command account-lifecycle shows CONTRACT.md §25 — the operations that get an
// account into the state §1's Login/VerifyMfa/Refresh/Logout already assume:
// email verification, both MFA enrolment paths, and password reset.
package main

import (
	"context"
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

	if err := startAPasswordReset(context.Background(), client, "alice@example.com"); err != nil {
		log.Printf("reset: %v", err)
	}
}

// enrolTotp is voluntary enrolment, by a signed-in user.
//
// Two calls, and deliberately no one-call helper: the human step in the middle
// — scanning the URI, reading a code off a phone — is not something a composed
// helper can wait for, and one that returned after MfaEnroll would report MFA
// as enabled when it is not (§25.2 rule 4).
func enrolTotp(ctx context.Context, client *axiam.Client, codeFromUser string) error {
	enrolment, err := client.MfaEnroll(ctx)
	if err != nil {
		return err
	}

	// TotpURI CONTAINS the secret: it is otpauth://...?secret=... . Both are
	// Sensitive for that reason, and the URI is the one that actually reaches a
	// log, because it is the one you hand to a QR renderer (§25.3).
	renderQR(enrolment.TotpURI.String())

	enabled, err := client.MfaConfirm(ctx, codeFromUser)
	if err != nil {
		return err
	}
	fmt.Printf("TOTP active: %v\n", enabled)
	return nil
}

// signIn handles the enrolment a tenant may demand.
//
// Before contract 1.28 the 403 mfa_setup_required answer reached callers as an
// *AuthzError — telling them they lacked permission to log in, when what the
// server said was recoverable and came with the means to recover. It is an
// outcome now (§25.2 rule 1), which is the whole reason this function can be
// written at all.
func signIn(ctx context.Context, client *axiam.Client, email, password, codeFromUser string) error {
	result, err := client.Login(ctx, email, password)
	if err != nil {
		return err
	}

	switch {
	case result.MFASetupRequired:
		enrolment, err := client.MfaSetupEnroll(ctx, result.SetupToken)
		if err != nil {
			return err
		}
		renderQR(enrolment.TotpURI.String())
		// This completes the login that was interrupted, and adopts
		// credentials exactly as Login would have (§25.2 rule 2).
		if _, err := client.MfaSetupConfirm(ctx, result.SetupToken, codeFromUser); err != nil {
			return err
		}
		fmt.Println("enrolled and signed in")
	case result.MFARequired:
		if _, err := client.VerifyMfa(ctx, result.MFAToken, codeFromUser); err != nil {
			return err
		}
		fmt.Println("signed in with the second factor")
	default:
		fmt.Println("signed in")
	}
	return nil
}

// startAPasswordReset asks for a reset mail.
//
// Returns nil WHETHER OR NOT THE ADDRESS EXISTS, and this SDK exposes no way to
// tell the difference. That is not an omission to improve on: any signal
// distinguishing them — including one inferred from timing — turns the endpoint
// into the account enumeration oracle its uniform response exists to prevent
// (§25.4).
func startAPasswordReset(ctx context.Context, client *axiam.Client, email string) error {
	if err := client.RequestPasswordReset(ctx, axiam.PasswordResetRequest{Email: email}); err != nil {
		return err
	}
	fmt.Println("if that address has an account, a reset mail is on its way")
	return nil
}

// finishAPasswordReset sets the new password.
//
// The context call is not optional on a tenant that might have OPAQUE enabled
// (§23): the client has to build a registration record, and building one needs
// parameters it cannot know before it has a token to ask with. Sending a
// plaintext password to a tenant in opaque_mode: required is refused, and
// refused late.
func finishAPasswordReset(ctx context.Context, client *axiam.Client, tokenFromLink, newPassword, tenantID string) error {
	resetContext, err := client.PasswordResetContext(ctx, axiam.Sensitive(tokenFromLink))
	if err != nil {
		return err
	}

	var opaque map[string]any
	if resetContext.Opaque != nil {
		enrolment, err := client.OpaqueEnrollment(ctx, newPassword)
		if err != nil {
			return err
		}
		opaque = map[string]any{"registration_record": enrolment.RegistrationRecord}
	}

	if err := client.ConfirmPasswordReset(ctx, axiam.PasswordResetConfirmation{
		Token:       axiam.Sensitive(tokenFromLink),
		NewPassword: axiam.Sensitive(newPassword),
		TenantID:    tenantID,
		Opaque:      opaque,
	}); err != nil {
		return err
	}
	fmt.Println("password changed")
	return nil
}

// renderQR stands in for showing the enrolment URI to a human.
//
// It is handed the REDACTED form on purpose: an example that printed the real
// secret would be the exact mistake §25.3 exists to prevent. A real caller
// passes enrolment.TotpURI to a QR renderer without stringifying it first.
func renderQR(totpURI string) {
	fmt.Printf("scan this: %s\n", totpURI)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

var (
	_ = enrolTotp
	_ = signIn
	_ = finishAPasswordReset
)
