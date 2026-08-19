// SRP-6a protocol arithmetic (CONTRACT.md §23).
//
// This file performs no I/O. It is the group constants, PAD(), the two KDFs
// the server may name, and the client half of the exchange. LoginSrp in
// srp_login.go is the two HTTP calls and the policy around them.

package axiam

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"crypto/pbkdf2"

	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------------------
// §23.4 Groups — RFC 5054 Appendix A
//
// These are embedded as constants and a modulus is NEVER accepted from the
// server: a server-supplied N is a server-supplied trapdoor. srp_test.go
// asserts the width, primality and safe-primality of each one, because a
// transcription slip here is a silent, total break that a client/server
// round-trip cannot catch — both sides would share the same wrong constant.
// ---------------------------------------------------------------------------

const (
	// GroupRFC5054_2048 is the RFC 5054 Appendix A 2048-bit group (g = 2).
	GroupRFC5054_2048 = "rfc5054_2048"
	// GroupRFC5054_3072 is the RFC 5054 Appendix A 3072-bit group (g = 5).
	GroupRFC5054_3072 = "rfc5054_3072"
	// GroupRFC5054_4096 is the RFC 5054 Appendix A 4096-bit group (g = 5).
	// AXIAM's default: it matches the RSA-4096 floor the project already sets
	// for certificates.
	GroupRFC5054_4096 = "rfc5054_4096"
)

const (
	// KdfArgon2id is the memory-hard KDF AXIAM asks for by default.
	KdfArgon2id = "argon2id"
	// KdfPBKDF2SHA256 is the fallback for runtimes with no vetted Argon2.
	KdfPBKDF2SHA256 = "pbkdf2_sha256"
)

const n2048Hex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
	"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
	"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
	"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

const n3072Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
	"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
	"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
	"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
	"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
	"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
	"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
	"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

const n4096Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
	"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
	"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
	"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
	"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
	"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
	"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
	"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8" +
	"DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
	"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"

// srpGroup is one RFC 5054 group: the modulus, the generator, and the byte
// width every hashed value is padded to.
type srpGroup struct {
	name    string
	n       *big.Int
	g       *big.Int
	byteLen int
}

func mustGroup(name, nHex string, g int64) *srpGroup {
	n, ok := new(big.Int).SetString(nHex, 16)
	if !ok {
		panic("axiam: malformed SRP modulus constant for " + name)
	}
	return &srpGroup{name: name, n: n, g: big.NewInt(g), byteLen: len(nHex) / 2}
}

var srpGroups = map[string]*srpGroup{
	GroupRFC5054_2048: mustGroup(GroupRFC5054_2048, n2048Hex, 2),
	GroupRFC5054_3072: mustGroup(GroupRFC5054_3072, n3072Hex, 5),
	GroupRFC5054_4096: mustGroup(GroupRFC5054_4096, n4096Hex, 5),
}

// parseSrpGroup resolves a wire group name, refusing anything it does not
// recognise (§23.4).
//
// NetworkError and not AuthError: this is a client capability gap, and §2
// reserves AuthError for wrong credentials. Reporting it as one would send a
// user off to reset a password that works.
func parseSrpGroup(name string) (*srpGroup, error) {
	if group, ok := srpGroups[name]; ok {
		return group, nil
	}
	return nil, &NetworkError{Message: fmt.Sprintf(
		"SRP: this SDK does not implement group %q; it embeds only %s, %s and %s",
		name, GroupRFC5054_2048, GroupRFC5054_3072, GroupRFC5054_4096)}
}

// ---------------------------------------------------------------------------
// §23.3 rule 1 — PAD() and the hash helpers
// ---------------------------------------------------------------------------

// srpPad renders v as exactly byteLen big-endian bytes.
//
// Skipping this is the classic SRP interop bug: two implementations agree
// until a value happens to have a leading zero byte, and then roughly one
// login in 256 fails in a way that reads as a flaky network.
func srpPad(v *big.Int, byteLen int) []byte {
	out := make([]byte, byteLen)
	v.FillBytes(out)
	return out
}

func srpHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func srpHashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(srpHash(parts...))
}

// srpMultiplier is k = H(N | PAD(g)); it depends only on the group.
func srpMultiplier(group *srpGroup) *big.Int {
	return srpHashInt(srpPad(group.n, group.byteLen), srpPad(group.g, group.byteLen))
}

// ---------------------------------------------------------------------------
// §23.3 rules 3 and 4 — x is a KDF output, not a hash
// ---------------------------------------------------------------------------

// SrpKdfParams are the KDF and cost the server dictates for one exchange.
//
// §23.3 rule 4: they arrive per exchange and are honoured as given. They are
// deliberately not cached across logins — a verifier enrolled under different
// costs is still valid and has to keep working.
type SrpKdfParams struct {
	// Kdf is "argon2id" or "pbkdf2_sha256".
	Kdf string
	// Iterations is Argon2id's time cost, or PBKDF2's iteration count.
	Iterations uint32
	// MemoryKiB is Argon2id's memory cost; ignored for PBKDF2.
	MemoryKiB uint32
	// Parallelism is Argon2id's lane count; ignored for PBKDF2.
	Parallelism uint8
}

// srpDeriveX computes x = KDF(identity ":" password, salt) as raw bytes.
//
// The caller reduces mod N. The identity is the one the server named in the
// challenge, never what the human typed (§23.3 rule 2).
func srpDeriveX(identity, password string, salt []byte, params SrpKdfParams) ([]byte, error) {
	secret := []byte(identity + ":" + password)
	defer zeroBytes(secret)

	switch params.Kdf {
	case KdfArgon2id:
		iterations := params.Iterations
		if iterations == 0 {
			iterations = 2
		}
		memory := params.MemoryKiB
		if memory == 0 {
			memory = 19456
		}
		lanes := params.Parallelism
		if lanes == 0 {
			lanes = 1
		}
		return argon2.IDKey(secret, salt, iterations, memory, lanes, 32), nil
	case KdfPBKDF2SHA256:
		iterations := int(params.Iterations)
		if iterations <= 0 {
			iterations = 600000
		}
		return pbkdf2.Key(sha256.New, string(secret), salt, iterations, 32)
	default:
		// Never substitute the other KDF: it derives a different x and
		// surfaces as "invalid password", the single most misleading failure
		// available here.
		return nil, &NetworkError{Message: fmt.Sprintf(
			"SRP: this SDK does not implement KDF %q; it implements %s and %s",
			params.Kdf, KdfArgon2id, KdfPBKDF2SHA256)}
	}
}

// zeroBytes overwrites b (§23.3 rule 8).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// The client half of the exchange
// ---------------------------------------------------------------------------

// srpClientSession holds one exchange's ephemeral secret between the challenge
// request and the proof that answers it.
type srpClientSession struct {
	group *srpGroup
	aPriv *big.Int
	// aPub is A = g^a mod N as lowercase hex, PAD()ed to the group width.
	aPub string
}

// beginSrpSession draws a fresh 256-bit a and computes A (§23.3 rule 7).
//
// There is no way to supply a: reusing one across exchanges leaks the
// relationship between two session secrets.
func beginSrpSession(group *srpGroup) (*srpClientSession, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("SRP: no entropy for the client ephemeral: %v", err)}
	}
	// Set the top bit so a is unambiguously >= 2^255.
	raw[0] |= 0x80
	return newSrpSession(group, new(big.Int).SetBytes(raw)), nil
}

func newSrpSession(group *srpGroup, aPriv *big.Int) *srpClientSession {
	aPub := new(big.Int).Exp(group.g, aPriv, group.n)
	return &srpClientSession{
		group: group,
		aPriv: aPriv,
		aPub:  hex.EncodeToString(srpPad(aPub, group.byteLen)),
	}
}

// srpProofs is what the client sends and what it expects back.
type srpProofs struct {
	// clientProof is M1, hex.
	clientProof string
	// expectedServerProof is the M2 the server must return (§23.3 rule 6).
	expectedServerProof string
}

// finish completes the exchange: S, K, M1 and the expected M2.
//
// identity is the server's, saltHex and serverPublicHex come from the
// challenge response, and x is srpDeriveX's output.
func (s *srpClientSession) finish(identity, saltHex, serverPublicHex string, x []byte) (srpProofs, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return srpProofs{}, &NetworkError{Message: "SRP: the server's salt is not valid hex"}
	}
	bPubBytes, err := hex.DecodeString(serverPublicHex)
	if err != nil {
		return srpProofs{}, &NetworkError{Message: "SRP: the server's public value is not valid hex"}
	}

	group := s.group
	bPub := new(big.Int).SetBytes(bPubBytes)

	// §23.3 rule 5. B ≡ 0 is a broken or hostile server, not a wrong password:
	// the classic SRP break, in which S becomes predictable and the exchange
	// would authenticate against a server that never knew the verifier.
	if new(big.Int).Mod(bPub, group.n).Sign() == 0 {
		return srpProofs{}, &NetworkError{Message: "SRP: the server sent an invalid public value (B mod N == 0)"}
	}

	aPubBytes, err := hex.DecodeString(s.aPub)
	if err != nil { // unreachable: s.aPub is produced by hex.EncodeToString.
		return srpProofs{}, &NetworkError{Message: "SRP: internal encoding fault"}
	}

	// u = H(PAD(A) | PAD(B))
	u := srpHashInt(aPubBytes, srpPad(bPub, group.byteLen))
	if u.Sign() == 0 {
		return srpProofs{}, &NetworkError{Message: "SRP: the server's parameters produce u == 0"}
	}

	xInt := new(big.Int).Mod(new(big.Int).SetBytes(x), group.n)

	// S = (B - k*g^x)^(a + u*x) mod N
	k := srpMultiplier(group)
	kgx := new(big.Int).Mul(k, new(big.Int).Exp(group.g, xInt, group.n))
	kgx.Mod(kgx, group.n)
	base := new(big.Int).Sub(new(big.Int).Mod(bPub, group.n), kgx)
	base.Mod(base, group.n) // big.Int.Mod is Euclidean: the result is non-negative.
	exponent := new(big.Int).Add(s.aPriv, new(big.Int).Mul(u, xInt))
	sharedSecret := new(big.Int).Exp(base, exponent, group.n)

	sBytes := srpPad(sharedSecret, group.byteLen)
	defer zeroBytes(sBytes)
	sessionKey := srpHash(sBytes)
	defer zeroBytes(sessionKey)

	// M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
	hn := srpHash(srpPad(group.n, group.byteLen))
	hg := srpHash(srpPad(group.g, group.byteLen))
	hxor := make([]byte, len(hn))
	for i := range hn {
		hxor[i] = hn[i] ^ hg[i]
	}
	hi := srpHash([]byte(identity))
	bPubPadded := srpPad(bPub, group.byteLen)
	m1 := srpHash(hxor, hi, salt, aPubBytes, bPubPadded, sessionKey)

	// M2 = H(PAD(A) | M1 | K)
	m2 := srpHash(aPubBytes, m1, sessionKey)

	return srpProofs{
		clientProof:         hex.EncodeToString(m1),
		expectedServerProof: hex.EncodeToString(m2),
	}, nil
}

// srpVerifyServerProof compares the server's M2 against the expected one in
// constant time (§23.3 rule 6).
func srpVerifyServerProof(expected, actual string) bool {
	if actual == "" || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(expected)), []byte(strings.ToLower(actual))) == 1
}

// ---------------------------------------------------------------------------
// §23.5 enrolment
// ---------------------------------------------------------------------------

// SrpEnrollmentRequest is the input to Client.SrpEnrollment.
type SrpEnrollmentRequest struct {
	// Identity is the account's USERNAME — the canonical identity the
	// challenge endpoint hands back. An email here produces a verifier no
	// login can ever satisfy.
	Identity string
	// Password is the plaintext being enrolled. It never leaves this process.
	Password string
	// Group is the tenant's group, from GET /api/v1/auth/me or the reset
	// context. Empty means the AXIAM default.
	Group string
	// Kdf is the tenant's KDF. Empty means argon2id.
	Kdf string
	// Iterations, MemoryKiB and Parallelism are the tenant's costs; zero
	// means the AXIAM default for the chosen KDF.
	Iterations  uint32
	MemoryKiB   uint32
	Parallelism uint8
}

// SrpEnrollment is the `srp` object §23.5 defines, ready to marshal onto any
// request that sets a password.
type SrpEnrollment struct {
	Group       string `json:"group"`
	Kdf         string `json:"kdf"`
	MemoryKiB   uint32 `json:"memory_kib,omitempty"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism,omitempty"`
	Salt        string `json:"salt"`
	Verifier    string `json:"verifier"`
}

// SrpEnrollment computes a verifier for a password, to send with any request
// that sets one: POST /api/v1/users, /auth/password/change,
// /auth/reset/confirm and /admin/bootstrap (§23.3 rule 11).
//
// The server cannot compute this — it never sees the plaintext — so it has to
// arrive with the request or not at all. The salt is 32 fresh bytes from
// crypto/rand.
//
// This is a method on Client only so it sits beside LoginSrp in the API; it
// performs no I/O and needs no open client.
func (c *Client) SrpEnrollment(req SrpEnrollmentRequest) (SrpEnrollment, error) {
	groupName := req.Group
	if groupName == "" {
		groupName = GroupRFC5054_4096
	}
	group, err := parseSrpGroup(groupName)
	if err != nil {
		return SrpEnrollment{}, err
	}

	params := SrpKdfParams{
		Kdf:         req.Kdf,
		Iterations:  req.Iterations,
		MemoryKiB:   req.MemoryKiB,
		Parallelism: req.Parallelism,
	}
	if params.Kdf == "" {
		params.Kdf = KdfArgon2id
	}
	switch params.Kdf {
	case KdfArgon2id:
		if params.Iterations == 0 {
			params.Iterations = 2
		}
		if params.MemoryKiB == 0 {
			params.MemoryKiB = 19456
		}
		if params.Parallelism == 0 {
			params.Parallelism = 1
		}
	case KdfPBKDF2SHA256:
		if params.Iterations == 0 {
			params.Iterations = 600000
		}
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return SrpEnrollment{}, &NetworkError{Message: fmt.Sprintf("SRP: no entropy for the enrolment salt: %v", err)}
	}

	x, err := srpDeriveX(req.Identity, req.Password, salt, params)
	if err != nil {
		return SrpEnrollment{}, err
	}
	defer zeroBytes(x)

	xInt := new(big.Int).Mod(new(big.Int).SetBytes(x), group.n)
	verifier := new(big.Int).Exp(group.g, xInt, group.n)

	out := SrpEnrollment{
		Group:      group.name,
		Kdf:        params.Kdf,
		Iterations: params.Iterations,
		Salt:       hex.EncodeToString(salt),
		Verifier:   hex.EncodeToString(srpPad(verifier, group.byteLen)),
	}
	if params.Kdf == KdfArgon2id {
		out.MemoryKiB = params.MemoryKiB
		out.Parallelism = params.Parallelism
	}
	return out, nil
}

// SrpAvailable reports whether this SDK build can perform SRP.
//
// Always true for Go: math/big is in the standard library and both KDFs are
// available (crypto/pbkdf2, golang.org/x/crypto/argon2). It exists because
// §23.1 puts it in the locked method vocabulary for every SDK, and in PHP —
// which needs ext-gmp or ext-bcmath and is guaranteed neither — it genuinely
// answers false.
func (c *Client) SrpAvailable() bool { return true }
