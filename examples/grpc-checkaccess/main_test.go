package main

import (
	"context"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestTokenCache_SetGet(t *testing.T) {
	c := newTokenCache()
	if _, ok := c.get(); ok {
		t.Fatal("an empty cache must report ok=false")
	}
	c.set("access-tok")
	got, ok := c.get()
	if !ok || got != "access-tok" {
		t.Fatalf("cache get = %q ok=%v", got, ok)
	}
}

// TestAuthInterceptor proves the example's interceptor injects the bearer +
// tenant metadata when a token is cached, and injects nothing when it is not —
// mirroring the grpc package's own (unexported) interceptor (§5).
func TestAuthInterceptor(t *testing.T) {
	t.Run("token present -> metadata injected", func(t *testing.T) {
		cache := newTokenCache()
		cache.set("access-tok")
		interceptor := authInterceptor(cache, "tenant-1")

		var gotMD metadata.MD
		invoker := func(ctx context.Context, _ string, _, _ any, _ *grpclib.ClientConn, _ ...grpclib.CallOption) error {
			gotMD, _ = metadata.FromOutgoingContext(ctx)
			return nil
		}
		if err := interceptor(context.Background(), "/svc/Method", nil, nil, nil, invoker); err != nil {
			t.Fatalf("interceptor: %v", err)
		}
		if got := gotMD.Get("authorization"); len(got) != 1 || got[0] != "Bearer access-tok" {
			t.Fatalf("authorization metadata = %v", got)
		}
		if got := gotMD.Get("x-tenant-id"); len(got) != 1 || got[0] != "tenant-1" {
			t.Fatalf("x-tenant-id metadata = %v", got)
		}
	})

	t.Run("no token -> nothing injected but invoker still runs", func(t *testing.T) {
		interceptor := authInterceptor(newTokenCache(), "tenant-1")
		var called bool
		invoker := func(ctx context.Context, _ string, _, _ any, _ *grpclib.ClientConn, _ ...grpclib.CallOption) error {
			called = true
			if md, _ := metadata.FromOutgoingContext(ctx); len(md) != 0 {
				t.Fatalf("expected no outgoing metadata, got %v", md)
			}
			return nil
		}
		if err := interceptor(context.Background(), "/svc/Method", nil, nil, nil, invoker); err != nil {
			t.Fatalf("interceptor: %v", err)
		}
		if !called {
			t.Fatal("the interceptor must still invoke the RPC when no token is cached")
		}
	})
}

func TestGetenv(t *testing.T) {
	t.Setenv("AXIAM_TEST_GRPC_KEY", "from-env")
	if got := getenv("AXIAM_TEST_GRPC_KEY", "fallback"); got != "from-env" {
		t.Fatalf("expected the env value, got %q", got)
	}
	if got := getenv("AXIAM_TEST_GRPC_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("expected the fallback, got %q", got)
	}
}
