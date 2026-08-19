// CONTRACT.md §23.7 conformance for the SRP-6a client.
//
// srp-test-vectors.json is generated from the AXIAM server implementation and
// vendored into every SDK. Eleven independent SRP implementations do not
// interoperate by accident; this is the file that says whether this one does.
//
// §23.7 rule 1 requires every intermediate to be reproduced, not only the
// final proof — an SDK that gets u wrong should find out at u rather than at
// "login sometimes fails".

package axiam

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type srpVector struct {
	Group         string `json:"group"`
	Identity      string `json:"identity"`
	Salt          string `json:"salt"`
	X             string `json:"x"`
	K             string `json:"k"`
	Verifier      string `json:"verifier"`
	APriv         string `json:"a_priv"`
	APub          string `json:"a_pub"`
	BPriv         string `json:"b_priv"`
	BPub          string `json:"b_pub"`
	U             string `json:"u"`
	SessionSecret string `json:"session_secret"`
	SessionKey    string `json:"session_key"`
	ClientProof   string `json:"client_proof"`
	ServerProof   string `json:"server_proof"`
}

// loadSrpVectors walks up from the test's working directory to find the
// vendored fixture, so the test does not encode how deep in the tree it runs.
func loadSrpVectors(t *testing.T) []srpVector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "srp-test-vectors.json")
		if raw, err := os.ReadFile(candidate); err == nil {
			var doc struct {
				Vectors []srpVector `json:"vectors"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("parse %s: %v", candidate, err)
			}
			return doc.Vectors
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("srp-test-vectors.json not found in any parent directory")
		}
		dir = parent
	}
}

func mustHexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("not hex: %q", s)
	}
	return v
}

// TestSrpGroupConstants covers §23.7 rule 4.
//
// A transcription slip in a modulus is a silent, total break: client and
// server would still agree with each other while the discrete-log hardness
// the protocol rests on quietly vanished. A round-trip test cannot catch it,
// because both sides share the same wrong constant.
func TestSrpGroupConstants(t *testing.T) {
	widths := map[string]int{
		GroupRFC5054_2048: 2048,
		GroupRFC5054_3072: 3072,
		GroupRFC5054_4096: 4096,
	}
	for name, bits := range widths {
		group := srpGroups[name]
		if group == nil {
			t.Fatalf("%s: not embedded", name)
		}
		if group.n.BitLen() != bits {
			t.Errorf("%s: modulus is %d bits, expected %d", name, group.n.BitLen(), bits)
		}
		if group.byteLen != bits/8 {
			t.Errorf("%s: byteLen %d does not match %d bits", name, group.byteLen, bits)
		}
		if !group.n.ProbablyPrime(24) {
			t.Errorf("%s: modulus is not prime", name)
		}
		// A safe prime: N = 2q + 1 with q prime.
		q := new(big.Int).Rsh(new(big.Int).Sub(group.n, big.NewInt(1)), 1)
		if !q.ProbablyPrime(24) {
			t.Errorf("%s: (N-1)/2 is not prime — not a safe prime", name)
		}
		// g generates the order-q subgroup iff g^q == N-1 for a safe prime.
		if got := new(big.Int).Exp(group.g, q, group.n); got.Cmp(new(big.Int).Sub(group.n, big.NewInt(1))) != 0 {
			t.Errorf("%s: g does not generate the large subgroup", name)
		}
	}
}

// TestSrpRefusesUnknownGroup covers §23.4: refuse rather than guess.
func TestSrpRefusesUnknownGroup(t *testing.T) {
	_, err := parseSrpGroup("rfc5054_1024")
	if err == nil {
		t.Fatal("expected a refusal for an unrecognised group")
	}
	// NetworkError, not AuthError: this is a client capability gap, and
	// calling it an auth failure would send a user to reset a working
	// password.
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected ErrNetwork, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "rfc5054_1024") {
		t.Fatalf("the message should name the group it cannot do: %v", err)
	}
}

// TestSrpRefusesUnknownKdf covers §23.3 rule 4.
func TestSrpRefusesUnknownKdf(t *testing.T) {
	// Substituting the other KDF derives a different x and surfaces as
	// "invalid password" — the single most misleading failure this code
	// could produce.
	_, err := srpDeriveX("alice", "pw", make([]byte, 32), SrpKdfParams{Kdf: "scrypt", Iterations: 1})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected ErrNetwork, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "scrypt") {
		t.Fatalf("the message should name the KDF it cannot do: %v", err)
	}
}

// TestSrpPad covers §23.3 rule 1 directly.
func TestSrpPad(t *testing.T) {
	if got := hex.EncodeToString(srpPad(big.NewInt(1), 4)); got != "00000001" {
		t.Fatalf("PAD(1, 4) = %s", got)
	}
	if got := hex.EncodeToString(srpPad(big.NewInt(0x0102), 2)); got != "0102" {
		t.Fatalf("PAD(0x0102, 2) = %s", got)
	}
}

// TestSrpFixturesCoverTheirCases guards the fixture itself: if these stop
// holding, everything below silently stops testing what it was built to test.
func TestSrpFixturesCoverTheirCases(t *testing.T) {
	vectors := loadSrpVectors(t)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	var leadingZeroSalt, leadingZeroX, nonASCII bool
	seen := map[string]bool{}
	for _, v := range vectors {
		leadingZeroSalt = leadingZeroSalt || strings.HasPrefix(v.Salt, "00")
		leadingZeroX = leadingZeroX || strings.HasPrefix(v.X, "00")
		nonASCII = nonASCII || func() bool {
			for i := 0; i < len(v.Identity); i++ {
				if v.Identity[i] > 0x7f {
					return true
				}
			}
			return false
		}()
		seen[v.Group] = true
	}
	if !leadingZeroSalt {
		t.Error("§23.7 rule 2: no vector has a leading-zero salt")
	}
	if !leadingZeroX {
		t.Error("§23.7 rule 2: no vector has a leading-zero x")
	}
	if !nonASCII {
		t.Error("§23.7 rule 3: no vector has a non-ASCII identity")
	}
	for _, g := range []string{GroupRFC5054_2048, GroupRFC5054_3072, GroupRFC5054_4096} {
		if !seen[g] {
			t.Errorf("no vector covers %s", g)
		}
	}
}

// TestSrpVectorsReproduceEveryIntermediate covers §23.7 rule 1.
func TestSrpVectorsReproduceEveryIntermediate(t *testing.T) {
	for _, v := range loadSrpVectors(t) {
		t.Run(v.Group+"/"+v.Identity, func(t *testing.T) {
			group, err := parseSrpGroup(v.Group)
			if err != nil {
				t.Fatalf("group: %v", err)
			}
			x := new(big.Int).Mod(mustHexInt(t, v.X), group.n)

			// k = H(N | PAD(g))
			if got := hex.EncodeToString(srpPad(srpMultiplier(group), 32)); got != v.K {
				t.Fatalf("k: got %s want %s", got, v.K)
			}

			// v = g^x mod N
			verifier := new(big.Int).Exp(group.g, x, group.n)
			if got := hex.EncodeToString(srpPad(verifier, group.byteLen)); got != v.Verifier {
				t.Fatalf("verifier: got %s want %s", got, v.Verifier)
			}

			// A = g^a mod N
			a := mustHexInt(t, v.APriv)
			aPub := new(big.Int).Exp(group.g, a, group.n)
			if got := hex.EncodeToString(srpPad(aPub, group.byteLen)); got != v.APub {
				t.Fatalf("A: got %s want %s", got, v.APub)
			}

			// B = (k*v + g^b) mod N
			b := mustHexInt(t, v.BPriv)
			bPub := new(big.Int).Add(
				new(big.Int).Mul(srpMultiplier(group), verifier),
				new(big.Int).Exp(group.g, b, group.n),
			)
			bPub.Mod(bPub, group.n)
			if got := hex.EncodeToString(srpPad(bPub, group.byteLen)); got != v.BPub {
				t.Fatalf("B: got %s want %s", got, v.BPub)
			}

			// u = H(PAD(A) | PAD(B))
			u := srpHashInt(srpPad(aPub, group.byteLen), srpPad(bPub, group.byteLen))
			if got := hex.EncodeToString(srpPad(u, 32)); got != v.U {
				t.Fatalf("u: got %s want %s", got, v.U)
			}

			// S and K, from the client's derivation.
			kgx := new(big.Int).Mul(srpMultiplier(group), new(big.Int).Exp(group.g, x, group.n))
			kgx.Mod(kgx, group.n)
			base := new(big.Int).Sub(bPub, kgx)
			base.Mod(base, group.n)
			s := new(big.Int).Exp(base, new(big.Int).Add(a, new(big.Int).Mul(u, x)), group.n)
			if got := hex.EncodeToString(srpPad(s, group.byteLen)); got != v.SessionSecret {
				t.Fatalf("S: got %s want %s", got, v.SessionSecret)
			}
			if got := hex.EncodeToString(srpHash(srpPad(s, group.byteLen))); got != v.SessionKey {
				t.Fatalf("K: got %s want %s", got, v.SessionKey)
			}
		})
	}
}

// TestSrpVectorsProduceContractProofs drives the real session rather than the
// helpers, with a pinned to the vector's value — otherwise this would only
// test the internals (§23.7 rule 1, and rules 2 and 3 through the fixtures).
func TestSrpVectorsProduceContractProofs(t *testing.T) {
	for _, v := range loadSrpVectors(t) {
		t.Run(v.Group+"/"+v.Identity, func(t *testing.T) {
			group, err := parseSrpGroup(v.Group)
			if err != nil {
				t.Fatalf("group: %v", err)
			}
			session := newSrpSession(group, mustHexInt(t, v.APriv))
			if session.aPub != v.APub {
				t.Fatalf("A: got %s want %s", session.aPub, v.APub)
			}
			x, err := hex.DecodeString(v.X)
			if err != nil {
				t.Fatalf("x: %v", err)
			}
			proofs, err := session.finish(v.Identity, v.Salt, v.BPub, x)
			if err != nil {
				t.Fatalf("finish: %v", err)
			}
			if proofs.clientProof != v.ClientProof {
				t.Fatalf("M1: got %s want %s", proofs.clientProof, v.ClientProof)
			}
			if proofs.expectedServerProof != v.ServerProof {
				t.Fatalf("M2: got %s want %s", proofs.expectedServerProof, v.ServerProof)
			}
		})
	}
}

// TestSrpRefusesZeroServerPublic covers §23.7 rule 6, with no network round
// trip: the classic SRP break, in which a client that accepts B ≡ 0 derives a
// predictable S and would authenticate against a server that never knew the
// verifier.
func TestSrpRefusesZeroServerPublic(t *testing.T) {
	group := srpGroups[GroupRFC5054_2048]
	session, err := beginSrpSession(group)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	zero := strings.Repeat("0", group.byteLen*2)
	_, err = session.finish("alice", strings.Repeat("00", 32), zero, make([]byte, 32))
	if err == nil {
		t.Fatal("expected a refusal for B mod N == 0")
	}
	if !strings.Contains(err.Error(), "invalid public value") {
		t.Fatalf("unexpected message: %v", err)
	}
}

// TestSrpUsesAFreshEphemeral covers §23.3 rule 7.
func TestSrpUsesAFreshEphemeral(t *testing.T) {
	group := srpGroups[GroupRFC5054_2048]
	first, err := beginSrpSession(group)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	second, err := beginSrpSession(group)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if first.aPub == second.aPub {
		t.Fatal("two exchanges produced the same A — a is being reused")
	}
}

// TestSrpKdfBindsIdentityPasswordAndSalt: every one of these must change the
// output, or a verifier would be replayable against a different account or a
// different salt.
func TestSrpKdfBindsIdentityPasswordAndSalt(t *testing.T) {
	params := SrpKdfParams{Kdf: KdfPBKDF2SHA256, Iterations: 1000}
	salt := []byte(strings.Repeat("a", 32))
	base, err := srpDeriveX("alice", "pw", salt, params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(base) != 32 {
		t.Fatalf("x is %d bytes, expected 32", len(base))
	}
	for _, tc := range []struct {
		name           string
		id, pw         string
		salt           []byte
		wantSameAsBase bool
	}{
		{"same inputs", "alice", "pw", salt, true},
		{"other identity", "bob", "pw", salt, false},
		{"other password", "alice", "pw2", salt, false},
		{"other salt", "alice", "pw", []byte(strings.Repeat("b", 32)), false},
	} {
		got, err := srpDeriveX(tc.id, tc.pw, tc.salt, params)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if same := hex.EncodeToString(got) == hex.EncodeToString(base); same != tc.wantSameAsBase {
			t.Errorf("%s: same-as-base = %v, want %v", tc.name, same, tc.wantSameAsBase)
		}
	}
}

// TestSrpArgon2idRuns exercises the default KDF the server asks for. Low
// memory so the test stays fast; the code path is identical to the 19 MiB
// production parameters.
func TestSrpArgon2idRuns(t *testing.T) {
	x, err := srpDeriveX("alice", "pw", make([]byte, 32), SrpKdfParams{
		Kdf: KdfArgon2id, Iterations: 1, MemoryKiB: 8192, Parallelism: 1,
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(x) != 32 {
		t.Fatalf("x is %d bytes, expected 32", len(x))
	}
}

// TestSrpVerifyServerProof covers the comparison half of §23.3 rule 6.
func TestSrpVerifyServerProof(t *testing.T) {
	proof := loadSrpVectors(t)[0].ServerProof
	if !srpVerifyServerProof(proof, proof) {
		t.Error("a matching proof must verify")
	}
	if srpVerifyServerProof(proof, proof[:len(proof)-1]+"0") {
		t.Error("a one-character difference must not verify")
	}
	if srpVerifyServerProof(proof, proof[:32]) {
		t.Error("a truncated proof must not verify")
	}
	if srpVerifyServerProof(proof, "") {
		t.Error("an absent proof must not verify")
	}
}

// TestSrpEnrollment covers §23.3 rule 11.
func TestSrpEnrollment(t *testing.T) {
	client, err := NewClient("https://axiam.example.test", "acme")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	if !client.SrpAvailable() {
		t.Fatal("Go always has math/big and both KDFs")
	}

	first, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity: "alice", Password: "hunter2", Kdf: KdfPBKDF2SHA256, Iterations: 1000,
	})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if first.Group != GroupRFC5054_4096 {
		t.Errorf("default group: got %s", first.Group)
	}
	if len(first.Salt) != 64 {
		t.Errorf("salt is %d hex chars, expected 64 (32 bytes)", len(first.Salt))
	}
	if first.MemoryKiB != 0 || first.Parallelism != 0 {
		t.Error("pbkdf2 enrolment must not carry argon2 parameters")
	}

	// A reused salt would make every verifier in a tenant equally attackable
	// with one precomputation.
	second, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity: "alice", Password: "hunter2", Kdf: KdfPBKDF2SHA256, Iterations: 1000,
	})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if first.Salt == second.Salt {
		t.Fatal("two enrolments produced the same salt")
	}

	// The verifier must be reproducible from the salt the enrolment reports.
	group := srpGroups[first.Group]
	salt, err := hex.DecodeString(first.Salt)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	x, err := srpDeriveX("alice", "hunter2", salt, SrpKdfParams{Kdf: KdfPBKDF2SHA256, Iterations: 1000})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	want := new(big.Int).Exp(group.g, new(big.Int).Mod(new(big.Int).SetBytes(x), group.n), group.n)
	if got := hex.EncodeToString(srpPad(want, group.byteLen)); got != first.Verifier {
		t.Fatal("the reported verifier is not g^x for the reported salt")
	}
}

func TestSrpEnrollmentRefusesUnknownGroup(t *testing.T) {
	client, err := NewClient("https://axiam.example.test", "acme")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()
	if _, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity: "alice", Password: "pw", Group: "rfc5054_1024",
	}); !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected ErrNetwork, got %T: %v", err, err)
	}
}
