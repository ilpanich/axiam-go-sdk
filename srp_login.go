// LoginSrp — the SRP-6a login path (CONTRACT.md §23).
//
// A sibling of Login, not a replacement. It establishes the same fact — this
// principal knows the password — by a route that never puts the password on
// the wire, and returns the SAME LoginResult, so an application can switch a
// tenant to SRP without touching its own code (§23.1).

package axiam

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/refreshguard"
)

const (
	srpChallengePath = "/api/v1/auth/srp/challenge"
	srpVerifyPath    = "/api/v1/auth/srp/verify"
)

// srpOpeningGroup is the group an exchange opens in before the server has
// named one.
//
// The challenge response names the group, but A has to be computed BEFORE
// that response exists — so the first attempt guesses, and the exchange
// restarts if the server names another. The guess is AXIAM's own default, so
// the restart is the exceptional path rather than the normal one.
const srpOpeningGroup = GroupRFC5054_4096

type srpChallengeRequestBody struct {
	loginRequestBody
	ClientPublic string `json:"client_public"`
}

// MarshalJSON emits the login body's fields plus client_public, and omits
// `password` — it has no business on this request.
func (b srpChallengeRequestBody) MarshalJSON() ([]byte, error) {
	inner, err := json.Marshal(b.loginRequestBody)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(inner, &fields); err != nil {
		return nil, err
	}
	delete(fields, "password")
	public, err := json.Marshal(b.ClientPublic)
	if err != nil {
		return nil, err
	}
	fields["client_public"] = public
	return json.Marshal(fields)
}

type srpChallengeResponseWire struct {
	SrpSession string `json:"srp_session"`
	// Identity is the canonical identity to feed into the KDF — the server's
	// answer, not the user's input (§23.3 rule 2). A user may sign in with a
	// username or an email while only one of the two is bound into x.
	Identity    string `json:"identity"`
	Salt        string `json:"salt"`
	Group       string `json:"group"`
	Kdf         string `json:"kdf"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	BPub        string `json:"b_pub"`
}

type srpVerifyRequestBody struct {
	SrpSession  string `json:"srp_session"`
	ClientProof string `json:"client_proof"`
}

type srpVerifyResponseWire struct {
	loginSuccessResponseWire
	mfaRequiredResponseWire
	ServerProof string `json:"server_proof"`
}

// LoginSrp performs the SRP-6a login exchange: POST /api/v1/auth/srp/challenge
// followed by POST /api/v1/auth/srp/verify (CONTRACT.md §23).
//
// It takes the same arguments as Login and returns the same LoginResult,
// including the MFARequired branch, so a caller needs one result handler for
// both paths.
//
// # What this does that Login does not
//
// The password never leaves this process. What crosses the wire is A and a
// proof, neither of which is useful without the account's verifier — so a
// TLS-terminating proxy, an accidentally verbose request log, or a heap dump
// on the server cannot capture a plaintext password, because the server never
// has one. It does NOT protect against a compromised AXIAM server.
//
// # Errors
//
//   - *NetworkError when the tenant has SRP disabled (the endpoint answers
//     404 — a property of the tenant, not of any user), and when this SDK
//     cannot perform the group or KDF the server named. These are client-side
//     faults, deliberately not *AuthError: reporting them as a credential
//     failure would send a user off to reset a password that works.
//   - *AuthError for a wrong password, and for a server whose M2 does not
//     verify. In the latter case no session is returned and the cookie jar is
//     cleared: an endpoint that cannot prove it holds the verifier is not the
//     server it claims to be (§23.3 rule 6).
//
// # Cost
//
// Runs the tenant's KDF: Argon2id at 19 MiB by default, tens to hundreds of
// milliseconds of CPU and the memory to go with it. That cost is the point.
func (c *Client) LoginSrp(ctx context.Context, usernameOrEmail, password string) (LoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return LoginResult{}, err
	}
	c.onCredentialChange()

	session, challenge, err := c.srpExchange(ctx, usernameOrEmail, srpOpeningGroup)
	if err != nil {
		return LoginResult{}, err
	}

	// The server named a group other than the one A was computed in, so the
	// exchange has to restart. Rare — the opening guess is AXIAM's own
	// default — but a tenant on a narrower group must work rather than fail.
	if challenge.Group != srpOpeningGroup {
		if _, err := parseSrpGroup(challenge.Group); err != nil {
			return LoginResult{}, err
		}
		session, challenge, err = c.srpExchange(ctx, usernameOrEmail, challenge.Group)
		if err != nil {
			return LoginResult{}, err
		}
	}

	salt, err := hex.DecodeString(challenge.Salt)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: "SRP: the server's salt is not valid hex"}
	}

	// challenge.Identity, never usernameOrEmail (§23.3 rule 2).
	x, err := srpDeriveX(challenge.Identity, password, salt, SrpKdfParams{
		Kdf:         challenge.Kdf,
		Iterations:  challenge.Iterations,
		MemoryKiB:   challenge.MemoryKiB,
		Parallelism: challenge.Parallelism,
	})
	if err != nil {
		return LoginResult{}, err
	}
	defer zeroBytes(x)

	proofs, err := session.finish(challenge.Identity, challenge.Salt, challenge.BPub, x)
	if err != nil {
		return LoginResult{}, err
	}

	payload, err := json.Marshal(srpVerifyRequestBody{
		SrpSession:  challenge.SrpSession,
		ClientProof: proofs.clientProof,
	})
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode SRP verify request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, srpVerifyPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return LoginResult{}, mapErrorResponse(resp)
	}

	var wire srpVerifyResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return LoginResult{}, deserErr(err)
	}

	// Mutual authentication (§23.3 rule 6), checked BEFORE anything from the
	// response is absorbed or reported. A rogue server that cannot prove
	// itself must not get the chance to collect an MFA code either — and any
	// cookies it set are discarded rather than left in the jar.
	if !srpVerifyServerProof(proofs.expectedServerProof, wire.ServerProof) {
		c.discardSessionCookies()
		c.onCredentialChange()
		return LoginResult{}, &AuthError{
			Message: "SRP: the server failed to prove it holds this account's verifier",
		}
	}

	if resp.StatusCode == http.StatusAccepted {
		return LoginResult{
			MFARequired:      true,
			MFAToken:         Sensitive(wire.ChallengeToken),
			AvailableMethods: wire.AvailableMethods,
		}, nil
	}

	if err := c.absorbSessionCookies(); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionID: wire.SessionID.String(), ExpiresIn: wire.ExpiresIn}, nil
}

// srpExchange opens an exchange in groupName and returns the session and the
// challenge that answers it.
//
// Split out because the group the server names may differ from the one A was
// computed in, in which case LoginSrp runs this a second time rather than
// continuing in the wrong group.
func (c *Client) srpExchange(
	ctx context.Context, usernameOrEmail, groupName string,
) (*srpClientSession, srpChallengeResponseWire, error) {
	var challenge srpChallengeResponseWire

	group, err := parseSrpGroup(groupName)
	if err != nil {
		return nil, challenge, err
	}
	session, err := beginSrpSession(group)
	if err != nil {
		return nil, challenge, err
	}

	// Reuses the login body builder so tenant/org resolution cannot drift
	// between the two login paths.
	body := srpChallengeRequestBody{
		loginRequestBody: c.buildLoginBody(usernameOrEmail, ""),
		ClientPublic:     session.aPub,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, challenge, &NetworkError{
			Message: fmt.Sprintf("failed to encode SRP challenge request: %v", err),
		}
	}

	req, err := c.newRequest(ctx, http.MethodPost, srpChallengePath, bytes.NewReader(payload))
	if err != nil {
		return nil, challenge, err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, challenge, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 404 is a property of the tenant ("SRP is off here"), not of the
		// user, and not a credential failure — so a caller can fall back to
		// Login without mistaking it for a bad password.
		return nil, challenge, &NetworkError{
			Message: "SRP: this tenant does not offer Secure Remote Password " +
				"(srp_mode is disabled); use Login instead",
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, challenge, mapErrorResponse(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return nil, challenge, deserErr(err)
	}
	return session, challenge, nil
}

// discardSessionCookies evicts the session cookies from the jar.
//
// The ordinary way a cookie leaves the jar is the server expiring it, which
// is exactly what is unavailable here: the only caller is the M2 mismatch in
// LoginSrp, where the response came from an endpoint that just failed to
// prove it holds the verifier. §23.3 rule 6 requires the session to be
// discarded "including any cookies the response set", so the client evicts
// them itself rather than trusting the other side to.
func (c *Client) discardSessionCookies() {
	jar := c.httpc.Jar
	if jar == nil {
		return
	}
	expired := make([]*http.Cookie, 0, 2)
	for _, name := range []string{accessCookie, refreshCookie} {
		expired = append(expired, &http.Cookie{
			Name:    name,
			Value:   "",
			Path:    "/",
			MaxAge:  -1,
			Expires: time.Unix(0, 0),
		})
	}
	jar.SetCookies(c.baseURL, expired)
	c.guard.Store(&refreshguard.Guard{})
}
