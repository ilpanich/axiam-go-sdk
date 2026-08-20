// OPAQUE (RFC 9807) — the protocol half. See opaque_login.go for the HTTP half.
//
// # Why this SDK has an implementation at all
//
// CONTRACT.md §23.1 forbids an SDK from implementing OPAQUE, with exactly one
// exception, and this is it: Go binds github.com/bytemare/opaque rather than
// the shared crates/axiam-opaque C ABI. Two reasons, and both are required —
// a vetted, independently maintained RFC 9807 implementation exists for Go,
// and binding the C ABI would force cgo on every consumer, breaking
// CGO_ENABLED=0 builds and cross-compilation for anyone who depends on this
// module.
//
// Even so, this file wraps a library; it does not implement a protocol. The
// SRP code it replaces was ~470 lines of modular arithmetic, RFC 5054 group
// constants and a hand-rolled KDF, written because SRP is arithmetic every
// language has. OPAQUE is not.
//
// # Keeping the exception honest
//
// "Both implement RFC 9807" is not evidence that two implementations
// interoperate. They must agree on the OPRF, the key schedule, the envelope,
// the AKE transcript AND the key-stretching parameters — and only the first
// four are in the specification. The KSF is where it would actually break,
// because opaque-ke stretches with a 16-byte all-zero salt and a 64-byte
// output and nothing in the RFC says it must.
//
// So it is checked rather than assumed: opaque_interop_test.go completes a
// full registration and login against the Rust implementation's server half.
// If that test ever fails, one side moved, and the answer is to find out
// which — not to loosen the test.

package axiam

import (
	"crypto"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

// opaqueKSFSaltLength is the salt width opaque-ke stretches with.
//
// Sixteen zero bytes. RFC 9807 stretches a value that is already an OPRF
// output over the password, so it carries full entropy from the KSF's point of
// view and there is nothing for a salt to separate — which is why a constant
// is sound here and would not be for a password hash. The *value* is not in
// the RFC, so it is part of AXIAM's cross-language contract rather than the
// protocol's, and it must match crates/axiam-opaque exactly.
const opaqueKSFSaltLength = 16

// opaqueKSFOutputLength is the stretched output width, matching the hash.
const opaqueKSFOutputLength = 64

// opaqueConfiguration is AXIAM's ciphersuite: OPAQUE-3DH over ristretto255
// with SHA-512, HKDF-SHA-512 and HMAC-SHA-512 — RFC 9807's recommended
// configuration, and byte-identical to crates/axiam-opaque's.
func opaqueConfiguration() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KSF:     ksf.Argon2id,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: nil,
	}
}

// OpaqueKsfParams are the key-stretching parameters a server named.
//
// Flat and optional, matching the wire format: the fields that do not apply to
// the named function are absent, NOT zero. Reading an absent field as 0 would
// stretch with the wrong cost and fail against a record that is perfectly
// good (§23.4 rule 5).
type OpaqueKsfParams struct {
	Ksf         string `json:"ksf"`
	MemoryKiB   *uint32 `json:"memory_kib,omitempty"`
	Iterations  *uint32 `json:"iterations,omitempty"`
	Parallelism *uint32 `json:"parallelism,omitempty"`
	LogN        *uint8  `json:"log_n,omitempty"`
	R           *uint32 `json:"r,omitempty"`
	P           *uint32 `json:"p,omitempty"`
}

// clientOptions turns what the server named into the options both halves must
// agree on.
//
// Refuses rather than substituting: substituting produces a well-formed
// randomized password that no AXIAM server agrees with, reported to the user
// as a wrong password (§23.4 rule 3). A refusal is a *NetworkError — a
// client-side fault — never an *AuthError, which would send a user off to
// reset a password that works.
func (p OpaqueKsfParams) clientOptions() (*opaque.ClientOptions, error) {
	missing := func(field string) error {
		return &NetworkError{Message: "OPAQUE: the server named ksf `" + p.Ksf +
			"` without `" + field + "`"}
	}

	var params []uint64
	switch p.Ksf {
	case "argon2id":
		// bytemare/ksf orders Argon2id as (time, memory KiB, threads).
		if p.Iterations == nil {
			return nil, missing("iterations")
		}
		if p.MemoryKiB == nil {
			return nil, missing("memory_kib")
		}
		if p.Parallelism == nil {
			return nil, missing("parallelism")
		}
		if err := opaqueCheckArgon2id(*p.MemoryKiB, *p.Iterations, *p.Parallelism); err != nil {
			return nil, err
		}
		params = []uint64{uint64(*p.Iterations), uint64(*p.MemoryKiB), uint64(*p.Parallelism)}
	case "scrypt":
		if p.LogN == nil {
			return nil, missing("log_n")
		}
		if p.R == nil {
			return nil, missing("r")
		}
		if p.P == nil {
			return nil, missing("p")
		}
		if err := opaqueCheckScrypt(*p.LogN, *p.R, *p.P); err != nil {
			return nil, err
		}
		params = []uint64{uint64(*p.LogN), uint64(*p.R), uint64(*p.P)}
	default:
		return nil, &NetworkError{
			Message: "OPAQUE: this SDK cannot perform the key-stretching function the " +
				"server named (`" + p.Ksf + "`)",
		}
	}

	return &opaque.ClientOptions{
		KSFSalt:       make([]byte, opaqueKSFSaltLength),
		KSFParameters: params,
		KSFLength:     opaqueKSFOutputLength,
	}, nil
}

// Accepted cost bands, matching axiam_opaque::AxiamKsf.
//
// A server is trusted to name its own policy, not to name a cost that would
// wedge every device an account owns (§23.4 rule 4).
func opaqueCheckArgon2id(memoryKiB, iterations, parallelism uint32) error {
	switch {
	case memoryKiB < 8192 || memoryKiB > 1_048_576:
		return &NetworkError{Message: "OPAQUE: argon2id memory_kib out of range"}
	case iterations < 1 || iterations > 10:
		return &NetworkError{Message: "OPAQUE: argon2id iterations out of range"}
	case parallelism < 1 || parallelism > 16:
		return &NetworkError{Message: "OPAQUE: argon2id parallelism out of range"}
	}
	return nil
}

func opaqueCheckScrypt(logN uint8, r, p uint32) error {
	switch {
	case logN < 14 || logN > 20:
		return &NetworkError{Message: "OPAQUE: scrypt log_n out of range"}
	case r < 1 || r > 16:
		return &NetworkError{Message: "OPAQUE: scrypt r out of range"}
	case p < 1 || p > 16:
		return &NetworkError{Message: "OPAQUE: scrypt p out of range"}
	}
	return nil
}

// OpaqueAvailable reports whether this build can perform OPAQUE (§23.2).
//
// Always true for the Go SDK, which compiles the implementation in. It exists
// because §23.2 puts it in the locked method vocabulary for every SDK, and in
// the SDKs that load a native library or a WebAssembly module it genuinely
// answers false when that artifact is absent.
func (c *Client) OpaqueAvailable() bool { return true }
