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
	OpaqueKsfParams
}

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
	OpaqueSession       string `json:"opaque_session"`
	RegistrationRecord  string `json:"registration_record"`
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
	return LoginResult{SessionID: wire.SessionID.String(), ExpiresIn: wire.ExpiresIn}, nil
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

	payload, err := json.Marshal(opaqueRegisterStartRequestBody{
		workspaceBody:       c.buildWorkspaceBody(),
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
