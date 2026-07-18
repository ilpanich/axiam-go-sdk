package grpc

import (
	"context"
	"errors"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	axiam "github.com/ilpanich/axiam-go-sdk"
	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// scriptedConn is a fake grpc.ClientConnInterface that returns a scripted
// sequence of (reply, error) pairs across successive Invoke calls, so the
// AuthzClient's UNAUTHENTICATED single-flight-retry path (§9.3) can be proven
// without a live server — and without any insecure-transport surface, which
// CONTRACT.md §6 / SC#3 forbid anywhere in the module's Go source.
type scriptedConn struct {
	replies []proto.Message
	errs    []error
	calls   int
}

func (c *scriptedConn) Invoke(_ context.Context, _ string, _, reply any, _ ...grpclib.CallOption) error {
	i := c.calls
	c.calls++
	if i < len(c.errs) && c.errs[i] != nil {
		return c.errs[i]
	}
	if i < len(c.replies) && c.replies[i] != nil {
		proto.Merge(reply.(proto.Message), c.replies[i])
	}
	return nil
}

func (c *scriptedConn) NewStream(context.Context, *grpclib.StreamDesc, string, ...grpclib.CallOption) (grpclib.ClientStream, error) {
	return nil, errors.New("streaming not supported")
}

func TestAuthzClient_CheckAccess_Allowed(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.CheckAccessResponse{Allowed: true, DenyReason: ""}}}
	client := NewAuthzClient(conn, nil)

	allowed, reason, err := client.CheckAccess(context.Background(), CheckAccessRequest{
		TenantID: "t", SubjectID: "s", Action: "read", ResourceID: "r", Scope: "field",
	})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !allowed || reason != "" {
		t.Fatalf("expected allowed with no reason, got allowed=%v reason=%q", allowed, reason)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 RPC, got %d", conn.calls)
	}
}

func TestAuthzClient_CheckAccess_Denied(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.CheckAccessResponse{Allowed: false, DenyReason: "no grant"}}}
	allowed, reason, err := NewAuthzClient(conn, nil).CheckAccess(context.Background(), CheckAccessRequest{Action: "read"})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if allowed || reason != "no grant" {
		t.Fatalf("expected denied with reason, got allowed=%v reason=%q", allowed, reason)
	}
}

// TestAuthzClient_UnauthenticatedRefreshRetry proves §9.3: an UNAUTHENTICATED
// response drives the caller-supplied single-flight refresh exactly once, then
// retries the RPC once. A second UNAUTHENTICATED is returned, never retried.
func TestAuthzClient_UnauthenticatedRefreshRetry(t *testing.T) {
	t.Run("refresh then success", func(t *testing.T) {
		conn := &scriptedConn{
			errs:    []error{status.Error(codes.Unauthenticated, "expired"), nil},
			replies: []proto.Message{nil, &axiamv1.CheckAccessResponse{Allowed: true}},
		}
		var refreshCalls int
		refresh := func(context.Context) error { refreshCalls++; return nil }

		allowed, _, err := NewAuthzClient(conn, refresh).CheckAccess(context.Background(), CheckAccessRequest{})
		if err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed after successful retry")
		}
		if refreshCalls != 1 {
			t.Fatalf("expected exactly 1 refresh, got %d", refreshCalls)
		}
		if conn.calls != 2 {
			t.Fatalf("expected exactly 2 RPCs (original + one retry), got %d", conn.calls)
		}
	})

	t.Run("refresh error is returned, no retry", func(t *testing.T) {
		conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
		refreshErr := errors.New("refresh failed")
		refresh := func(context.Context) error { return refreshErr }

		_, _, err := NewAuthzClient(conn, refresh).CheckAccess(context.Background(), CheckAccessRequest{})
		if !errors.Is(err, refreshErr) {
			t.Fatalf("expected the refresh error to propagate, got %v", err)
		}
		if conn.calls != 1 {
			t.Fatalf("expected no retry after a failed refresh, got %d RPCs", conn.calls)
		}
	})

	t.Run("nil refresh maps UNAUTHENTICATED to AuthError immediately", func(t *testing.T) {
		conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
		_, _, err := NewAuthzClient(conn, nil).CheckAccess(context.Background(), CheckAccessRequest{})
		var authErr *axiam.AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *AuthError, got %T: %v", err, err)
		}
		if conn.calls != 1 {
			t.Fatalf("expected exactly 1 RPC with a nil refresh, got %d", conn.calls)
		}
	})
}

func TestAuthzClient_PermissionDeniedIsAuthzError(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.PermissionDenied, "forbidden")}}
	_, _, err := NewAuthzClient(conn, nil).CheckAccess(context.Background(), CheckAccessRequest{})
	var authzErr *axiam.AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T: %v", err, err)
	}
}

func TestAuthzClient_BatchCheck(t *testing.T) {
	t.Run("success preserves order", func(t *testing.T) {
		conn := &scriptedConn{replies: []proto.Message{&axiamv1.BatchCheckAccessResponse{
			Results: []*axiamv1.CheckAccessResponse{
				{Allowed: true},
				{Allowed: false, DenyReason: "second denied"},
			},
		}}}
		results, err := NewAuthzClient(conn, nil).BatchCheck(context.Background(), []CheckAccessRequest{
			{Action: "read", ResourceID: "r1"},
			{Action: "write", ResourceID: "r2"},
		})
		if err != nil {
			t.Fatalf("BatchCheck: %v", err)
		}
		if len(results) != 2 || !results[0].Allowed || results[1].Allowed || results[1].DenyReason != "second denied" {
			t.Fatalf("results not mapped in order: %+v", results)
		}
	})

	t.Run("unauthenticated drives refresh + retry", func(t *testing.T) {
		conn := &scriptedConn{
			errs:    []error{status.Error(codes.Unauthenticated, "expired"), nil},
			replies: []proto.Message{nil, &axiamv1.BatchCheckAccessResponse{Results: []*axiamv1.CheckAccessResponse{{Allowed: true}}}},
		}
		var refreshCalls int
		results, err := NewAuthzClient(conn, func(context.Context) error { refreshCalls++; return nil }).
			BatchCheck(context.Background(), []CheckAccessRequest{{Action: "read"}})
		if err != nil {
			t.Fatalf("BatchCheck: %v", err)
		}
		if refreshCalls != 1 || conn.calls != 2 || len(results) != 1 {
			t.Fatalf("unexpected retry behavior: refresh=%d calls=%d results=%d", refreshCalls, conn.calls, len(results))
		}
	})

	t.Run("refresh error propagates", func(t *testing.T) {
		conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
		refreshErr := errors.New("refresh boom")
		_, err := NewAuthzClient(conn, func(context.Context) error { return refreshErr }).
			BatchCheck(context.Background(), []CheckAccessRequest{{Action: "read"}})
		if !errors.Is(err, refreshErr) {
			t.Fatalf("expected refresh error, got %v", err)
		}
	})
}

func TestMapGRPCError_Table(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want func(error) bool
	}{
		{"unavailable -> network", status.Error(codes.Unavailable, "down"), func(e error) bool {
			var n *axiam.NetworkError
			return errors.As(e, &n)
		}},
		{"deadline -> network", status.Error(codes.DeadlineExceeded, "slow"), func(e error) bool {
			var n *axiam.NetworkError
			return errors.As(e, &n)
		}},
		{"non-status error -> network", errors.New("plain"), func(e error) bool {
			var n *axiam.NetworkError
			return errors.As(e, &n)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapGRPCError(tc.err); !tc.want(got) {
				t.Fatalf("mapGRPCError(%v) = %T, not the expected type", tc.err, got)
			}
		})
	}
}

func TestNewTLSCredentials_Exported(t *testing.T) {
	creds, err := NewTLSCredentials(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewTLSCredentials(nil, nil, nil): %v", err)
	}
	if creds.Info().SecurityProtocol != "tls" {
		t.Fatalf("expected tls protocol, got %q", creds.Info().SecurityProtocol)
	}
	if _, err := NewTLSCredentials([]byte("not a pem"), nil, nil); err == nil {
		t.Fatal("expected an error for an invalid custom CA PEM")
	}
}

func TestNewGRPCClient_Constructs(t *testing.T) {
	creds, err := NewTLSCredentials(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewTLSCredentials: %v", err)
	}
	// NewClient does not dial eagerly (grpc-go 1.63+), so construction against
	// an unreachable target must still succeed; connection errors surface on
	// the first RPC, not here.
	conn, err := NewGRPCClient("passthrough:///127.0.0.1:0", creds, nil)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	if conn == nil {
		t.Fatal("expected a non-nil ClientConn")
	}
	_ = conn.Close()
}
