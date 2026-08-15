// Enforcing CONTRACT.md §10.1 rule 9 in a resource server — the full rule,
// covering certificate-bound (RFC 8705) and DPoP-bound (RFC 9449) tokens.
//
// # What rule 9 actually says
//
// A token carrying "cnf" is NOT a bearer token. Accepting one without proving
// the caller holds the confirmed key converts it back into a bearer token and
// discards the whole protection the operator turned on.
//
// Three cases are worth internalising, because they are the ones implemented
// wrongly:
//
//  1. An UNBOUND token is still accepted — no certificate, no proof. Rule 9 is
//     not "require evidence from everybody".
//  2. A "cnf" naming BOTH methods is a conjunction. Two constraints means two;
//     satisfying the more convenient one is not compliance.
//  3. A "cnf" this SDK cannot interpret is REFUSED, never read as
//     unconstrained — including an empty one.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// One store per process. The in-memory store is per-instance, so a deployment
// running more than one replica needs a shared implementation (Redis, a
// database table) or each replica gets its own replay window.
var jtiStore = axiam.NewInMemoryDPoPJtiStore()

func main() {
	verifier, err := axiam.NewJWKSVerifier(context.Background(),
		os.Getenv("AXIAM_BASE_URL"), http.DefaultClient)
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}

	http.HandleFunc("/v1/things", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Rules 1-8: signature, expiry, issuer, audience. NOT rule 9 — this
		// call has no transport to ask, which is exactly why the binding check
		// is separate rather than something you can forget to opt into.
		claims, err := verifier.VerifyAccessToken(r.Context(), []byte(token),
			axiam.TokenValidationOptions{Tenant: os.Getenv("AXIAM_TENANT_ID")})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var proofs axiam.PresentedProofs

		// The thumbprint must come from the connection, never a header the
		// caller can set: a forgeable input makes the mechanism decorative.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			proofs.CertificateThumbprint =
				axiam.CertificateThumbprintS256(r.TLS.PeerCertificates[0].Raw)
		}

		// All ten §21.7.2 checks. Returns the proof key's thumbprint, so the
		// value handed to rule 9 below could only have come from a proof that
		// verified — a thumbprint lifted off an UNVERIFIED proof would let a
		// proof captured from any other endpoint authorize this one.
		if proof := r.Header.Get("DPoP"); proof != "" {
			jkt, err := axiam.VerifyDPoPProof(proof, axiam.DPoPRequest{
				Method:      r.Method,
				URI:         "https://" + r.Host + r.URL.Path,
				AccessToken: token,
			}, jtiStore)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			proofs.DPoPThumbprint = jkt
		}

		// Rule 9. Returns nil immediately for an unbound token, so adopting
		// this does not break existing deployments.
		if err := axiam.VerifyTokenBinding(claims, proofs); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Write([]byte("subject " + claims.Subject + " authorized\n"))
	})

	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}
