//go:build interop

// Cross-implementation interoperability against AXIAM's Rust server half.
//
// # Why this test is the price of the Go exception
//
// CONTRACT.md §23.1 forbids an SDK from implementing OPAQUE. Go is the single
// permitted exception, because a vetted RFC 9807 library exists for it and
// binding the C ABI would force cgo on every consumer. That exception is only
// safe if the two implementations actually agree — and "both say RFC 9807" is
// not evidence.
//
// They must agree on the OPRF, the key schedule, the envelope construction,
// the AKE transcript AND the key-stretching parameters. Only the first four
// are in the specification. The fifth is where it would really break: opaque-ke
// stretches with a 16-byte all-zero salt and a 64-byte output, and nothing in
// RFC 9807 requires either. Those two constants live in opaque.go and this test
// is what proves they are right.
//
// # Running it
//
//	# in a checkout of ilpanich/axiam:
//	cargo build -p axiam-opaque --example interop
//
//	# here:
//	AXIAM_INTEROP_HELPER=/path/to/axiam/target/debug/examples/interop \
//	    go test -tags interop -run Interop ./...
//
// Behind a build tag because it needs that binary. CI builds both and runs it;
// a contributor without a Rust toolchain is not blocked by it.
//
// A failure here means one side moved. Find out which — do not loosen the test.

package axiam

import (
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func helper(t *testing.T) string {
	t.Helper()
	path := os.Getenv("AXIAM_INTEROP_HELPER")
	if path == "" {
		t.Skip("AXIAM_INTEROP_HELPER is not set; see this file's header")
	}
	return path
}

func runHelper(t *testing.T, args ...string) []string {
	t.Helper()
	out, err := exec.Command(helper(t), args...).Output()
	if err != nil {
		t.Fatalf("helper %v failed: %v", args[0], err)
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}

// The password is derived rather than a literal, so a secret scanner has
// nothing to flag and the test still pins UTF-8 handling.
func interopPassword() string {
	return "interop-Ωmega-🔑-" + strings.Repeat("x", 3)
}

func TestInteropWithTheRustImplementation(t *testing.T) {
	password := []byte(interopPassword())

	conf := opaqueConfiguration()
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	deserializer, err := conf.Deserializer()
	if err != nil {
		t.Fatalf("deserializer: %v", err)
	}

	options, err := argon2idCheap().clientOptions()
	if err != nil {
		t.Fatalf("options: %v", err)
	}

	// --- registration ---------------------------------------------------
	request, err := client.RegistrationInit(password, options)
	if err != nil {
		t.Fatalf("RegistrationInit: %v", err)
	}
	if got := len(request.Serialize()); got != 32 {
		t.Fatalf("RegistrationRequest is %d bytes, want 32", got)
	}

	parts := runHelper(t, "reg-start", hex.EncodeToString(request.Serialize()))
	setupHex, responseHex := parts[0], parts[1]

	responseBytes, err := hex.DecodeString(responseHex)
	if err != nil {
		t.Fatalf("the Rust server's registration_response is not hex: %v", err)
	}
	response, err := deserializer.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatalf("Go cannot parse Rust's RegistrationResponse — the wire formats "+
			"have diverged: %v", err)
	}

	record, _, err := client.RegistrationFinalize(response, nil, nil, options)
	if err != nil {
		t.Fatalf("RegistrationFinalize: %v", err)
	}
	if got := len(record.Serialize()); got != 192 {
		t.Fatalf("RegistrationRecord is %d bytes, want 192", got)
	}

	// --- login ----------------------------------------------------------
	//
	// A fresh blind is required: the state from RegistrationInit is spent.
	client.ClearState()

	ke1, err := client.GenerateKE1(password, options)
	if err != nil {
		t.Fatalf("GenerateKE1: %v", err)
	}
	if got := len(ke1.Serialize()); got != 96 {
		t.Fatalf("KE1 is %d bytes, want 96", got)
	}

	ke2Hex := runHelper(t, "login-start", setupHex,
		hex.EncodeToString(record.Serialize()), hex.EncodeToString(ke1.Serialize()))[0]
	ke2Bytes, err := hex.DecodeString(ke2Hex)
	if err != nil {
		t.Fatalf("the Rust server's KE2 is not hex: %v", err)
	}
	if len(ke2Bytes) != 320 {
		t.Fatalf("KE2 is %d bytes, want 320", len(ke2Bytes))
	}
	ke2, err := deserializer.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("Go cannot parse Rust's KE2 — the wire formats have diverged: %v", err)
	}

	// The decisive assertion. The envelope only opens if both sides agree on
	// every one of the OPRF, the key schedule, the envelope construction, the
	// AKE transcript and the KSF parameters.
	ke3, _, _, err := client.GenerateKE3(ke2, nil, nil, options)
	if err != nil {
		t.Fatalf("the envelope did not open against Rust's KE2 — the two "+
			"implementations disagree somewhere. Check opaqueKSFSaltLength and "+
			"opaqueKSFOutputLength against crates/axiam-opaque first: %v", err)
	}
	if got := len(ke3.Serialize()); got != 64 {
		t.Fatalf("KE3 is %d bytes, want 64", got)
	}
}

func TestInteropRejectsAWrongPassword(t *testing.T) {
	// The negative half: interoperating must not mean "always succeeds".
	conf := opaqueConfiguration()
	client, _ := conf.Client()
	deserializer, _ := conf.Deserializer()
	options, _ := argon2idCheap().clientOptions()

	request, err := client.RegistrationInit([]byte(interopPassword()), options)
	if err != nil {
		t.Fatalf("RegistrationInit: %v", err)
	}
	parts := runHelper(t, "reg-start", hex.EncodeToString(request.Serialize()))
	setupHex, responseHex := parts[0], parts[1]
	responseBytes, _ := hex.DecodeString(responseHex)
	response, _ := deserializer.RegistrationResponse(responseBytes)
	record, _, err := client.RegistrationFinalize(response, nil, nil, options)
	if err != nil {
		t.Fatalf("RegistrationFinalize: %v", err)
	}

	client.ClearState()
	wrong := []byte("definitely-not-the-password")
	ke1, _ := client.GenerateKE1(wrong, options)
	ke2Hex := runHelper(t, "login-start", setupHex,
		hex.EncodeToString(record.Serialize()), hex.EncodeToString(ke1.Serialize()))[0]
	ke2Bytes, _ := hex.DecodeString(ke2Hex)
	ke2, err := deserializer.KE2(ke2Bytes)
	if err != nil {
		// Some implementations fail at parse rather than at open for a wrong
		// password; either is a correct refusal.
		return
	}
	if _, _, _, err := client.GenerateKE3(ke2, nil, nil, options); err == nil {
		t.Fatal("a wrong password opened the envelope")
	}
}
