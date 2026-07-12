package refreshguard

import "testing"

// TestGuard_CachedRefreshTokenAndExp proves the non-blocking accessors for the
// cached refresh token and expiry: both report ok=false before anything is
// cached, and read back the seeded triple afterward. These accessors back the
// gRPC interceptor's hot path, which must never take the refresh mutex.
func TestGuard_CachedRefreshTokenAndExp(t *testing.T) {
	g := &Guard{}
	if _, ok := g.CachedRefreshToken(); ok {
		t.Fatal("expected no cached refresh token before seeding")
	}
	if _, ok := g.CachedExp(); ok {
		t.Fatal("expected no cached exp before seeding")
	}

	g.Seed(Sensitive("access-tok"), Sensitive("refresh-tok"), 4102444800)

	access, ok := g.CachedAccessToken()
	if !ok || access != Sensitive("access-tok") {
		t.Fatalf("cached access = %q ok=%v", access, ok)
	}
	refresh, ok := g.CachedRefreshToken()
	if !ok || refresh != Sensitive("refresh-tok") {
		t.Fatalf("cached refresh = %q ok=%v", refresh, ok)
	}
	exp, ok := g.CachedExp()
	if !ok || exp != 4102444800 {
		t.Fatalf("cached exp = %d ok=%v", exp, ok)
	}
}

// TestGuard_SeedEmptyRefreshKeepsPrevious proves Seed's guard: seeding with an
// empty refresh token preserves the previously cached one (a refresh response
// that rotates only the access token must not blank the refresh token).
func TestGuard_SeedEmptyRefreshKeepsPrevious(t *testing.T) {
	g := &Guard{}
	g.Seed(Sensitive("access-1"), Sensitive("refresh-1"), 100)
	g.Seed(Sensitive("access-2"), Sensitive(""), 200)

	if refresh, _ := g.CachedRefreshToken(); refresh != Sensitive("refresh-1") {
		t.Fatalf("empty refresh in Seed must keep the previous value, got %q", refresh)
	}
	if access, _ := g.CachedAccessToken(); access != Sensitive("access-2") {
		t.Fatalf("access token should have been updated, got %q", access)
	}
	if exp, _ := g.CachedExp(); exp != 200 {
		t.Fatalf("exp should have been updated, got %d", exp)
	}
}
