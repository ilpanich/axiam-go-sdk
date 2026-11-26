package jwks

import "testing"

// GO-R1-3 and GO-R1-8 at the parse layer: a `roles` array with a null
// element is not an array of strings (absent, §11.2 rule 11 b), and `scope`
// is split on single spaces with empty entries dropped (rule 11 d).
func TestParseClaims_OI16_RolesAndScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payload  string
		hasRoles bool
		roles    []string
		scopes   []string
	}{
		{"null element", `{"roles":["admin",null]}`, false, nil, nil},
		{"only null", `{"roles":[null]}`, false, nil, nil},
		{"strings", `{"roles":["admin","reader"]}`, true, []string{"admin", "reader"}, nil},
		{"empty array", `{"roles":[]}`, true, []string{}, nil},
		{"scope single spaces", `{"scope":"openid  admin "}`, false, nil, []string{"openid", "admin"}},
		{"scope with a tab is one token", `{"scope":"openid\tadmin"}`, false, nil, []string{"openid\tadmin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseClaims([]byte(tc.payload))
			if err != nil {
				t.Fatalf("parseClaims: %v", err)
			}
			if c.HasRoles != tc.hasRoles || len(c.Roles) != len(tc.roles) {
				t.Fatalf("HasRoles=%v Roles=%q, want HasRoles=%v Roles=%q", c.HasRoles, c.Roles, tc.hasRoles, tc.roles)
			}
			for i := range tc.roles {
				if c.Roles[i] != tc.roles[i] {
					t.Fatalf("Roles=%q, want %q", c.Roles, tc.roles)
				}
			}
			if len(c.Scopes) != len(tc.scopes) {
				t.Fatalf("Scopes=%q, want %q", c.Scopes, tc.scopes)
			}
			for i := range tc.scopes {
				if c.Scopes[i] != tc.scopes[i] {
					t.Fatalf("Scopes=%q, want %q", c.Scopes, tc.scopes)
				}
			}
		})
	}
}

// An `aud` array with a null element is not an array of strings: it is a
// parse failure, so the token is rejected (review round 1, item 4).
func TestParseClaims_OI16_AudienceNullElementIsRejected(t *testing.T) {
	for _, payload := range []string{`{"aud":["axiam:user",null]}`, `{"aud":[null]}`} {
		if c, err := parseClaims([]byte(payload)); err == nil {
			t.Fatalf("parseClaims(%s) must fail, got Audience=%q", payload, c.Audience)
		}
	}
	if c, err := parseClaims([]byte(`{"aud":["axiam:user","x"]}`)); err != nil || len(c.Audience) != 2 {
		t.Fatalf("a string array must parse: %v %q", err, c.Audience)
	}
}
