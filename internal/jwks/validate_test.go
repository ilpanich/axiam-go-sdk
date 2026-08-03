package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// These tests exercise the CONTRACT.md §10.1 machinery at the PACKAGE level.
//
// The §10.1 behaviour is also covered end-to-end through the net/http guard
// (middleware/contract_10_1_test.go), but that suite reaches ValidateClaims
// only along the paths the middleware itself takes — it cannot express a
// nil-Exp Claims value directly, nor reach ValidationOptions.currentTime's
// real-clock branch, nor drive the parse helpers with wire shapes the typed
// Claims struct cannot represent. Testing the guard is not the same as
// testing the rules the guard delegates to.

// fixedNow returns a ValidationOptions clock seam pinned to ts.
func fixedNow(ts time.Time) func() time.Time { return func() time.Time { return ts } }

const (
	testTenant  = "11111111-1111-1111-1111-111111111111"
	otherTenant = "22222222-2222-2222-2222-222222222222"
)

// baseOpts is a minimally-valid ValidationOptions: tenant configured, no
// issuer/audience expectation, clock pinned.
func baseOpts(now time.Time) ValidationOptions {
	return ValidationOptions{Tenant: testTenant, now: fixedNow(now)}
}

// validClaims is a token that should pass every rule under baseOpts.
func validClaims(now time.Time) Claims {
	return Claims{
		Subject:  "user-1",
		TenantID: testTenant,
		Exp:      at(now.Add(15 * time.Minute)),
	}
}

func TestValidateClaims_AcceptsAValidToken(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)
	if err := ValidateClaims(validClaims(now), baseOpts(now)); err != nil {
		t.Fatalf("expected a valid token to pass, got %v", err)
	}
}

// Rule 4 — tenant_id. The JWKS trust anchor is organization-wide, so these
// are the cases that stop a sibling tenant's token being accepted.
func TestValidateClaims_Rule4Tenant(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)

	t.Run("unconfigured guard fails closed", func(t *testing.T) {
		opts := ValidationOptions{Tenant: "", now: fixedNow(now)}
		if err := ValidateClaims(validClaims(now), opts); !errors.Is(err, ErrNoConfiguredTenant) {
			t.Fatalf("want ErrNoConfiguredTenant, got %v", err)
		}
	})

	t.Run("absent tenant_id claim rejected", func(t *testing.T) {
		c := validClaims(now)
		c.TenantID = ""
		if err := ValidateClaims(c, baseOpts(now)); !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("want ErrTenantMismatch, got %v", err)
		}
	})

	t.Run("foreign tenant rejected", func(t *testing.T) {
		c := validClaims(now)
		c.TenantID = otherTenant
		if err := ValidateClaims(c, baseOpts(now)); !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("want ErrTenantMismatch, got %v", err)
		}
	})
}

// Rule 2 — exp is REQUIRED. A nil Exp is the SEC-080 defect: a permanent
// credential that a "check it only if present" guard waves through.
func TestValidateClaims_Rule2Exp(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)

	t.Run("absent exp rejected", func(t *testing.T) {
		c := validClaims(now)
		c.Exp = nil
		if err := ValidateClaims(c, baseOpts(now)); !errors.Is(err, ErrMissingExp) {
			t.Fatalf("want ErrMissingExp, got %v", err)
		}
	})

	t.Run("expired beyond leeway rejected", func(t *testing.T) {
		c := validClaims(now)
		c.Exp = at(now.Add(-ClockSkewLeeway - time.Second))
		if err := ValidateClaims(c, baseOpts(now)); !errors.Is(err, ErrExpired) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
	})

	t.Run("just-expired within leeway accepted", func(t *testing.T) {
		c := validClaims(now)
		c.Exp = at(now.Add(-ClockSkewLeeway + time.Second))
		if err := ValidateClaims(c, baseOpts(now)); err != nil {
			t.Fatalf("leeway should tolerate this, got %v", err)
		}
	})
}

// Rule 3 — nbf honoured when present, absent is valid.
func TestValidateClaims_Rule3Nbf(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)

	t.Run("absent nbf accepted", func(t *testing.T) {
		if err := ValidateClaims(validClaims(now), baseOpts(now)); err != nil {
			t.Fatalf("absent nbf must be valid, got %v", err)
		}
	})

	t.Run("past nbf accepted", func(t *testing.T) {
		c := validClaims(now)
		c.Nbf = at(now.Add(-time.Hour))
		if err := ValidateClaims(c, baseOpts(now)); err != nil {
			t.Fatalf("past nbf must be valid, got %v", err)
		}
	})

	t.Run("future nbf beyond leeway rejected", func(t *testing.T) {
		c := validClaims(now)
		c.Nbf = at(now.Add(ClockSkewLeeway + time.Second))
		if err := ValidateClaims(c, baseOpts(now)); !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("want ErrNotYetValid, got %v", err)
		}
	})

	t.Run("near-future nbf within leeway accepted", func(t *testing.T) {
		c := validClaims(now)
		c.Nbf = at(now.Add(ClockSkewLeeway - time.Second))
		if err := ValidateClaims(c, baseOpts(now)); err != nil {
			t.Fatalf("leeway should tolerate this, got %v", err)
		}
	})
}

// Rule 5 — iss is CONDITIONAL: unset expectation means no check, never
// "expect the empty string".
func TestValidateClaims_Rule5Issuer(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)

	t.Run("unconfigured issuer is not checked", func(t *testing.T) {
		c := validClaims(now)
		c.Issuer = "https://whatever.example"
		if err := ValidateClaims(c, baseOpts(now)); err != nil {
			t.Fatalf("unconfigured issuer must not be checked, got %v", err)
		}
	})

	t.Run("matching issuer accepted", func(t *testing.T) {
		c := validClaims(now)
		c.Issuer = "https://axiam.example"
		opts := baseOpts(now)
		opts.ExpectedIssuer = "https://axiam.example"
		if err := ValidateClaims(c, opts); err != nil {
			t.Fatalf("matching issuer must pass, got %v", err)
		}
	})

	t.Run("mismatched issuer rejected", func(t *testing.T) {
		c := validClaims(now)
		c.Issuer = "https://evil.example"
		opts := baseOpts(now)
		opts.ExpectedIssuer = "https://axiam.example"
		if err := ValidateClaims(c, opts); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("want ErrIssuerMismatch, got %v", err)
		}
	})

	t.Run("absent issuer under a configured expectation rejected", func(t *testing.T) {
		opts := baseOpts(now)
		opts.ExpectedIssuer = "https://axiam.example"
		if err := ValidateClaims(validClaims(now), opts); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("want ErrIssuerMismatch for an absent iss, got %v", err)
		}
	})
}

// Rule 6 — aud is CONDITIONAL. An absent aud can never CONTAIN the
// expectation, so it must fail closed once one is configured.
func TestValidateClaims_Rule6Audience(t *testing.T) {
	now := time.Unix(1_785_700_000, 0)

	t.Run("unconfigured audience is not checked", func(t *testing.T) {
		c := validClaims(now)
		c.Audience = []string{"someone-else"}
		if err := ValidateClaims(c, baseOpts(now)); err != nil {
			t.Fatalf("unconfigured audience must not be checked, got %v", err)
		}
	})

	t.Run("audience present in an array accepted", func(t *testing.T) {
		c := validClaims(now)
		c.Audience = []string{"other", "axiam:user"}
		opts := baseOpts(now)
		opts.ExpectedAudience = "axiam:user"
		if err := ValidateClaims(c, opts); err != nil {
			t.Fatalf("audience in array must pass, got %v", err)
		}
	})

	t.Run("mismatched audience rejected", func(t *testing.T) {
		c := validClaims(now)
		c.Audience = []string{"axiam:m2m"}
		opts := baseOpts(now)
		opts.ExpectedAudience = "axiam:user"
		if err := ValidateClaims(c, opts); !errors.Is(err, ErrAudienceMismatch) {
			t.Fatalf("want ErrAudienceMismatch, got %v", err)
		}
	})

	t.Run("absent audience under a configured expectation rejected", func(t *testing.T) {
		opts := baseOpts(now)
		opts.ExpectedAudience = "axiam:user"
		if err := ValidateClaims(validClaims(now), opts); !errors.Is(err, ErrAudienceMismatch) {
			t.Fatalf("want ErrAudienceMismatch for an absent aud, got %v", err)
		}
	})
}

// currentTime's real-clock branch: with no seam configured it must fall back
// to time.Now rather than a zero Time (which would make every token expired).
func TestValidationOptions_CurrentTimeDefaultsToWallClock(t *testing.T) {
	before := time.Now()
	got := ValidationOptions{Tenant: testTenant}.currentTime()
	after := time.Now()

	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Fatalf("currentTime() = %v, want a value between %v and %v", got, before, after)
	}

	// And a token valid against the wall clock passes with no seam at all.
	c := Claims{TenantID: testTenant, Exp: at(time.Now().Add(time.Hour))}
	if err := ValidateClaims(c, ValidationOptions{Tenant: testTenant}); err != nil {
		t.Fatalf("wall-clock validation should pass, got %v", err)
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b"}, "b") {
		t.Fatal("containsString should find a present value")
	}
	if containsString([]string{"a", "b"}, "c") {
		t.Fatal("containsString should not find an absent value")
	}
	if containsString(nil, "a") {
		t.Fatal("containsString on nil must be false — an absent aud contains nothing")
	}
	if containsString([]string{}, "") {
		t.Fatal("containsString on empty must be false")
	}
}

// numericDate: absent/null yield (nil, nil); a JSON string is the wrong type
// and is rejected rather than coerced; non-finite is rejected; a fractional
// NumericDate truncates toward zero (RFC 7519 permits a non-integer value).
func TestNumericDate(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    *int64
		wantErr bool
	}{
		{name: "absent", raw: "", want: nil},
		{name: "null", raw: "null", want: nil},
		{name: "integer", raw: "1700000000", want: secs(1_700_000_000)},
		{name: "fractional truncates", raw: "1700000000.9", want: secs(1_700_000_000)},
		{name: "negative", raw: "-5", want: secs(-5)},
		{name: "quoted numeric string rejected", raw: `"1700000000"`, wantErr: true},
		{name: "quoted text rejected", raw: `"soon"`, wantErr: true},
		{name: "boolean rejected", raw: "true", wantErr: true},
		{name: "object rejected", raw: `{"a":1}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := numericDate(json.RawMessage(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("want nil, got %d", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("want %d, got nil", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("want %d, got %d", *tc.want, *got)
			}
		})
	}
}

// audience: RFC 7519 §4.1.3 allows a single StringOrURI or an array of them.
func TestAudience(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "absent", raw: "", want: nil},
		{name: "null", raw: "null", want: nil},
		{name: "single string", raw: `"axiam:user"`, want: []string{"axiam:user"}},
		{name: "array", raw: `["a","b"]`, want: []string{"a", "b"}},
		{name: "empty array", raw: `[]`, want: []string{}},
		{name: "number rejected", raw: "42", wantErr: true},
		{name: "object rejected", raw: `{"aud":"a"}`, wantErr: true},
		{name: "array of numbers rejected", raw: `[1,2]`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := audience(json.RawMessage(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("want %v, got %v", tc.want, got)
				}
			}
		})
	}
}

// VerifyAccessToken is the guard entry point: signature (rule 1) THEN claims
// (rules 2-7). These prove it does not stop after the signature — which is
// precisely the difference between it and VerifySignatureOnlyUnchecked.
func TestVerifyAccessToken(t *testing.T) {
	priv, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	now := time.Now()

	t.Run("valid token returns claims", func(t *testing.T) {
		token := signEdDSA(t, priv, "kid-1", Claims{
			Subject: "user-1", TenantID: testTenant, Exp: at(now.Add(time.Hour)),
		})
		got, err := v.VerifyAccessToken(ctx, token, ValidationOptions{Tenant: testTenant})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if got.TenantID != testTenant {
			t.Fatalf("tenant = %q, want %q", got.TenantID, testTenant)
		}
	})

	t.Run("signature failure short-circuits before claim policy", func(t *testing.T) {
		// HS256 is refused by the alg allowlist before any keyset lookup, so
		// this must NOT surface as a claim error.
		if _, err := v.VerifyAccessToken(ctx, signHS256(t), ValidationOptions{Tenant: testTenant}); err == nil {
			t.Fatal("expected a signature-layer rejection")
		} else if errors.Is(err, ErrTenantMismatch) || errors.Is(err, ErrMissingExp) {
			t.Fatalf("signature failure must not be reported as a claim failure: %v", err)
		}
	})

	t.Run("signature-valid but foreign tenant is rejected", func(t *testing.T) {
		token := signEdDSA(t, priv, "kid-1", Claims{
			Subject: "user-1", TenantID: otherTenant, Exp: at(now.Add(time.Hour)),
		})
		if _, err := v.VerifyAccessToken(ctx, token, ValidationOptions{Tenant: testTenant}); !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("want ErrTenantMismatch, got %v", err)
		}
		// The raw primitive accepts exactly what the guard rejects — that
		// asymmetry is why it is named "...Unchecked".
		if _, err := v.VerifySignatureOnlyUnchecked(ctx, token); err != nil {
			t.Fatalf("raw primitive should accept a signature-valid token, got %v", err)
		}
	})

	t.Run("signature-valid but no exp is rejected", func(t *testing.T) {
		token := signEdDSA(t, priv, "kid-1", Claims{
			Subject: "user-1", TenantID: testTenant, // Exp deliberately nil
		})
		if _, err := v.VerifyAccessToken(ctx, token, ValidationOptions{Tenant: testTenant}); !errors.Is(err, ErrMissingExp) {
			t.Fatalf("want ErrMissingExp, got %v", err)
		}
		if _, err := v.VerifySignatureOnlyUnchecked(ctx, token); err != nil {
			t.Fatalf("raw primitive should accept it, got %v", err)
		}
	})
}
