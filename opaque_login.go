// LoginOpaque and OpaqueEnrollment — the OPAQUE (RFC 9807) HTTP paths
// (CONTRACT.md §23).
//
// A sibling of Login, not a replacement. It establishes the same fact — this
// principal knows the password — by a route that never puts the password on
// the wire, and returns the SAME LoginResult, so an application can switch a
// tenant to OPAQUE without touching its own code (§23.1).

package axiam

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

const (
	opaqueRegisterStartPath = "/api/v1/auth/opaque/register/start"
	opaqueLoginStartPath    = "/api/v1/auth/opaque/login/start"
	opaqueLoginFinishPath   = "/api/v1/auth/opaque/login/finish"
)

type opaqueLoginStartRequestBody struct {
	loginRequestBody
	KE1 string `json:"ke1"`
}

type opaqueLoginStartResponseWire struct {
	OpaqueSession string `json:"opaque_session"`
	KE2           string `json:"ke2"`
	Suite         string `json:"suite"`
	// Mode carries the tenant's opaque_mode — "optional" or "required",
	// never "disabled" (that path answers 404). Optional on the wire: a
	// server older than contract 1.29 does not send it, which decodes to ""
	// and is treated as "required" along with any value this SDK does not
	// recognise (§23.4 rule 7, fail closed).
	Mode string `json:"mode"`
	OpaqueKsfParams
}

// opaqueModeOptional is the one mode value that changes what happens after a
// failed KE2 (§23.4 rule 7). Everything else — "required", an unrecognised
// value, or the field's absence — ends the exchange.
const opaqueModeOptional = "optional"

type opaqueLoginFinishRequestBody struct {
	OpaqueSession string `json:"opaque_session"`
	KE3           string `json:"ke3"`
}

type opaqueRegisterStartRequestBody struct {
	workspaceBody
	RegistrationRequest string `json:"registration_request"`
}

type opaqueRegisterStartResponseWire struct {
	OpaqueSession        string `json:"opaque_session"`
	RegistrationResponse string `json:"registration_response"`
	Suite                string `json:"suite"`
	OpaqueKsfParams
}

// OpaqueEnrollment is a completed registration record, to send with any
// request that sets a password.
//
// Two fields, where the SRP verifier it replaces had seven. The server chose
// the credential identifier, the ciphersuite and the costs and sealed them
// into OpaqueSession — which is why a client cannot name any of them, and why
// it cannot enrol a record against somebody else's account.
type OpaqueEnrollment struct {
	OpaqueSession      string `json:"opaque_session"`
	RegistrationRecord string `json:"registration_record"`
}

// LoginOpaque performs a full OPAQUE login (CONTRACT.md §23).
//
// Returns the same LoginResult as Login, including the MFA-challenge case, so
// a caller needs one result handler for both.
//
// # What this does that Login does not
//
// The password never leaves this process. What crosses the wire is a blinded
// group element and a MAC, neither useful without the account's record AND the
// tenant's OPRF seed — so a TLS-terminating proxy, an accidentally verbose
// request log or a heap dump on the server cannot capture a plaintext
// password, because the server never has one. It also means a stolen record
// database is not offline-crackable on its own, which is the property SRP
// could not offer.
//
// It does NOT protect against a compromised AXIAM server.
//
// # What a caller no longer has to do
//
// Under SRP this returned only after verifying the server's M2, and §23.3
// rule 6 had to mandate that in capitals because skipping it kept only the
// half of the protocol that authenticates the client. RFC 9807's AKE
// authenticates the server during the handshake — opening KE2 IS the proof
// that the server holds the record — so there is no separate check and no way
// for a caller to omit one.
//
// # Errors
//
//   - *NetworkError when the tenant has OPAQUE disabled (the endpoint answers
//     404 — a property of the tenant, not of any user), and when this SDK
//     cannot perform the KSF the server named. These are client-side or
//     configuration faults, deliberately not *AuthError: reporting them as a
//     credential failure would send a user off to reset a password that works,
//     and would stop a caller falling back to Login.
//   - *AuthError for a wrong password, an account that does not exist, and a
//     server that does not hold the record — indistinguishable by design.
//     Nothing is sent to login/finish in that case (§23.4 rule 7).
//
// # When a failed exchange falls back to Login (§23.4 rule 7)
//
// A failure to open KE2 ends the OPAQUE exchange — no KE3 is ever sent — but
// it is not always the end of the login. The login/start response carries the
// tenant's mode, and that alone decides:
//
//   - "optional": this call retries the same credentials over Login before
//     reporting anything, and returns that call's result or its error. Under
//     optional an account with no registration record is the ordinary case,
//     not a failure — every account has none until its password is next set —
//     so reporting the failed exchange would lock out every user of a tenant
//     part-way through a migration.
//   - "required", an unrecognised value, or no mode field at all (a server
//     older than contract 1.29): *AuthError, and Login is NOT tried. Such a
//     tenant refuses /auth/login for every principal anyway, so the retry
//     would only put a plaintext password on the wire.
//
// The mode field is NOT downgrade protection and must not be read as such: a
// hostile server that wanted the plaintext could answer 404 and get the
// caller's own fallback regardless of what it puts here. What closes that is
// server-side — required refuses /auth/login before examining any credential.
//
// # Cost
//
// Runs the tenant's key-stretching function: Argon2id at 19 MiB by default,
// tens to hundreds of milliseconds of CPU and the memory to go with it. That
// cost is the point — it is what makes a stolen record expensive to attack
// even by someone holding the OPRF seed.
func (c *Client) LoginOpaque(ctx context.Context, usernameOrEmail, password string) (LoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return LoginResult{}, err
	}
	c.onCredentialChange()

	conf := opaqueConfiguration()
	client, err := conf.Client()
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}
	deserializer, err := conf.Deserializer()
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}

	// The KSF parameters are not known until login/start answers, but KE1 does
	// not depend on them — unlike SRP, where the group had to be guessed and
	// the exchange restarted if the server named another. One round trip,
	// always.
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}

	payload, err := json.Marshal(opaqueLoginStartRequestBody{
		loginRequestBody: c.buildLoginBody(usernameOrEmail, ""),
		KE1:              hex.EncodeToString(ke1.Serialize()),
	})
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode OPAQUE login/start request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, opaqueLoginStartPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	// A property of the tenant, not of the user. Reported as a configuration
	// fault so a caller can fall back to Login without mistaking it for bad
	// credentials.
	if resp.StatusCode == http.StatusNotFound {
		return LoginResult{}, &NetworkError{
			Message: "this tenant does not offer OPAQUE (opaque_mode is disabled); use Login instead",
		}
	}
	if resp.StatusCode != http.StatusOK {
		return LoginResult{}, mapErrorResponse(resp)
	}

	var started opaqueLoginStartResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		return LoginResult{}, deserErr(err)
	}

	options, err := started.clientOptions()
	if err != nil {
		return LoginResult{}, err
	}

	ke2Bytes, err := hex.DecodeString(started.KE2)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: "OPAQUE: the server's KE2 is not valid hex"}
	}
	ke2, err := deserializer.KE2(ke2Bytes)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: "OPAQUE: the server's KE2 is malformed"}
	}

	// The whole of the client's authentication check. A failure here covers
	// both halves of the mutual authentication — the envelope only opens under
	// the right password, and KE2's MAC only verifies if the server actually
	// holds the record — and nothing further may be sent (§23.4 rule 7).
	ke3, _, _, err := client.GenerateKE3(ke2, nil, nil, options)
	if err != nil {
		// What happens now depends on the tenant's mode and on nothing else.
		//
		// Under "optional" an account with no registration record is the
		// ordinary case rather than an error: every account has none the
		// moment an operator enables OPAQUE, and they acquire one only as
		// they next set a password. Treating the failed exchange as final
		// would lock out every user of a tenant mid-migration, which is the
		// state "optional" exists to serve — so the same credentials go over
		// the password path, and that call's outcome is this call's outcome.
		//
		// Under "required" (and for any response with no mode field, which is
		// a server older than contract 1.29, and for any value not recognised
		// here) the exchange is over. /auth/login answers 403 opaque_required
		// for every principal in such a tenant, so retrying would put a
		// plaintext password on the wire for nothing.
		if started.Mode == opaqueModeOptional {
			return c.Login(ctx, usernameOrEmail, password)
		}
		return LoginResult{}, &AuthError{Message: "invalid credentials"}
	}

	payload, err = json.Marshal(opaqueLoginFinishRequestBody{
		OpaqueSession: started.OpaqueSession,
		KE3:           hex.EncodeToString(ke3.Serialize()),
	})
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode OPAQUE login/finish request: %v", err)}
	}

	req, err = c.newRequest(ctx, http.MethodPost, opaqueLoginFinishPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}
	resp, err = c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return LoginResult{}, mapErrorResponse(resp)
	}

	if resp.StatusCode == http.StatusAccepted {
		var wire mfaRequiredResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return LoginResult{}, deserErr(err)
		}
		return LoginResult{
			MFARequired:      true,
			MFAToken:         Sensitive(wire.ChallengeToken),
			AvailableMethods: wire.AvailableMethods,
		}, nil
	}

	var wire loginSuccessResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return LoginResult{}, deserErr(err)
	}
	if err := c.absorbSessionCookies(); err != nil {
		return LoginResult{}, err
	}
	result := LoginResult{
		SessionID:         wire.SessionID.String(),
		ExpiresIn:         wire.ExpiresIn,
		OrganizationLevel: wire.User.OrganizationLevel,
	}
	principalScope(wire.User, &result)
	// §5.2.2: remember where this principal lives, so a later
	// OpaqueEnrollmentForSelf seals against the account's own tenant
	// without a second round trip.
	c.setPrincipalTenantID(result.PrincipalTenantID)
	return result, nil
}

// OpaqueEnrollment builds a registration record for password, to send with any
// request that sets one (user creation, change-password, reset completion).
//
// This performs a register/start round trip, which the SRP verifier it
// replaces did not need: OPAQUE's envelope is sealed under the server's
// oblivious PRF, so there is no offline computation that produces a valid
// record.
//
// Note the absence of an identity argument. The SRP version required the
// account's canonical username, and passing an email produced a verifier no
// login could ever satisfy. A record binds to a credential identifier the
// server chooses, so there is nothing here to get wrong — and a later rename
// cannot invalidate it.
//
// # Errors
//
// *NetworkError when the tenant has OPAQUE disabled or this SDK cannot perform
// the KSF the server named.
func (c *Client) OpaqueEnrollment(ctx context.Context, password string) (*OpaqueEnrollment, error) {
	return c.enroll(ctx, password, nil)
}

// OpaqueEnrollmentForSelf builds a registration record for the CALLER'S OWN new
// password, sealed against the tenant the caller's account lives in.
//
// CONTRACT.md §5.2.2 rule 2. POST /auth/password/change and the record that
// accompanies it are about the account, not about whatever tenant the client is
// currently pointed at, and a record sealed against the acting tenant is
// refused with "the OPAQUE session was issued for a different tenant".
//
// The distinction only bites for an organization-level principal that has
// selected another tenant to act on; for everyone else the two tenants are the
// same value and this behaves identically to OpaqueEnrollment. It is still the
// method to call for a self-service password change, because which principal is
// signed in is not something the call site usually knows.
//
// Returns a NetworkError when no login has completed on this client yet — the
// principal tenant is reported by the login response, so there is nothing to
// seal against before then.
func (c *Client) OpaqueEnrollmentForSelf(ctx context.Context, password string) (*OpaqueEnrollment, error) {
	principalTenant := c.principalTenantID()
	if principalTenant == nil {
		return nil, &NetworkError{Message: "OPAQUE: no principal tenant is known yet — sign in before building a registration record for your own password"}
	}
	return c.enroll(ctx, password, principalTenant)
}

// enroll is the shared body of the two enrolment methods; they differ only in
// the tenant the record is sealed against.
func (c *Client) enroll(ctx context.Context, password string, principalTenant *uuid.UUID) (*OpaqueEnrollment, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	conf := opaqueConfiguration()
	client, err := conf.Client()
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}
	deserializer, err := conf.Deserializer()
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}

	request, err := client.RegistrationInit([]byte(password))
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}

	workspace := c.buildWorkspaceBody()
	if principalTenant != nil {
		// §5.2.2 rule 2: name the principal tenant by id and drop the slug.
		// A slug naming the acting tenant would out-vote the id server-side,
		// which is the exact confusion this override exists to avoid.
		workspace.TenantID = principalTenant
		workspace.TenantSlug = nil
	}
	payload, err := json.Marshal(opaqueRegisterStartRequestBody{
		workspaceBody:       workspace,
		RegistrationRequest: hex.EncodeToString(request.Serialize()),
	})
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to encode OPAQUE register/start request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, opaqueRegisterStartPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &NetworkError{
			Message: "this tenant does not offer OPAQUE (opaque_mode is disabled)",
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, mapErrorResponse(resp)
	}

	var started opaqueRegisterStartResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		return nil, deserErr(err)
	}

	options, err := started.clientOptions()
	if err != nil {
		return nil, err
	}

	responseBytes, err := hex.DecodeString(started.RegistrationResponse)
	if err != nil {
		return nil, &NetworkError{Message: "OPAQUE: the server's registration_response is not valid hex"}
	}
	response, err := deserializer.RegistrationResponse(responseBytes)
	if err != nil {
		return nil, &NetworkError{Message: "OPAQUE: the server's registration_response is malformed"}
	}

	// The client state carries the blind from RegistrationInit; clearing it
	// here would discard exactly what this call needs.
	record, _, err := client.RegistrationFinalize(response, nil, nil, options)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("OPAQUE: %v", err)}
	}

	return &OpaqueEnrollment{
		OpaqueSession:      started.OpaqueSession,
		RegistrationRecord: hex.EncodeToString(record.Serialize()),
	}, nil
}
