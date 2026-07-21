package grpc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	axiam "github.com/ilpanich/axiam-go-sdk"
	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

func strPtr(s string) *string { return &s }

// TestUserInfoClient_GetUserInfo_AllClaims proves the full claim set (both
// scope-gated optionals present) maps into the typed UserInfo (CONTRACT.md
// §1.1 return shape) in a single RPC.
func TestUserInfoClient_GetUserInfo_AllClaims(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.GetUserInfoResponse{
		Sub:               "user-uuid",
		TenantId:          "tenant-uuid",
		OrgId:             "org-uuid",
		Email:             strPtr("user@example.com"),
		PreferredUsername: strPtr("alice"),
	}}}

	info, err := NewUserInfoClient(conn, nil).GetUserInfo(context.Background())
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if info.Sub != "user-uuid" || info.TenantID != "tenant-uuid" || info.OrgID != "org-uuid" {
		t.Fatalf("required claims not mapped: %+v", info)
	}
	if info.Email == nil || *info.Email != "user@example.com" {
		t.Fatalf("expected email claim, got %v", info.Email)
	}
	if info.PreferredUsername == nil || *info.PreferredUsername != "alice" {
		t.Fatalf("expected preferred_username claim, got %v", info.PreferredUsername)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 RPC, got %d", conn.calls)
	}
}

// TestUserInfoClient_GetUserInfo_AbsentOptionals proves that when the token
// carries neither the "email" nor "profile" scope, the two optional claims are
// absent (nil), while the three always-present claims are still populated.
func TestUserInfoClient_GetUserInfo_AbsentOptionals(t *testing.T) {
	conn := &scriptedConn{replies: []proto.Message{&axiamv1.GetUserInfoResponse{
		Sub:      "user-uuid",
		TenantId: "tenant-uuid",
		OrgId:    "org-uuid",
	}}}

	info, err := NewUserInfoClient(conn, nil).GetUserInfo(context.Background())
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if info.Sub != "user-uuid" || info.TenantID != "tenant-uuid" || info.OrgID != "org-uuid" {
		t.Fatalf("required claims not mapped: %+v", info)
	}
	if info.Email != nil {
		t.Fatalf("expected nil email without the email scope, got %q", *info.Email)
	}
	if info.PreferredUsername != nil {
		t.Fatalf("expected nil preferred_username without the profile scope, got %q", *info.PreferredUsername)
	}
}

// TestUserInfoClient_UnauthenticatedRefreshRetry proves §9.3 for GetUserInfo:
// an UNAUTHENTICATED response drives the caller-supplied single-flight refresh
// exactly once, then retries the RPC once; a refresh error is returned without
// a retry, and a nil refresh maps UNAUTHENTICATED straight to AuthError.
func TestUserInfoClient_UnauthenticatedRefreshRetry(t *testing.T) {
	t.Run("refresh then success", func(t *testing.T) {
		conn := &scriptedConn{
			errs: []error{status.Error(codes.Unauthenticated, "expired"), nil},
			replies: []proto.Message{nil, &axiamv1.GetUserInfoResponse{
				Sub: "user-uuid", TenantId: "tenant-uuid", OrgId: "org-uuid",
			}},
		}
		var refreshCalls int
		refresh := func(context.Context) error { refreshCalls++; return nil }

		info, err := NewUserInfoClient(conn, refresh).GetUserInfo(context.Background())
		if err != nil {
			t.Fatalf("GetUserInfo: %v", err)
		}
		if info.Sub != "user-uuid" {
			t.Fatalf("expected claims after successful retry, got %+v", info)
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

		_, err := NewUserInfoClient(conn, refresh).GetUserInfo(context.Background())
		if !errors.Is(err, refreshErr) {
			t.Fatalf("expected the refresh error to propagate, got %v", err)
		}
		if conn.calls != 1 {
			t.Fatalf("expected no retry after a failed refresh, got %d RPCs", conn.calls)
		}
	})

	t.Run("nil refresh maps UNAUTHENTICATED to AuthError immediately", func(t *testing.T) {
		conn := &scriptedConn{errs: []error{status.Error(codes.Unauthenticated, "expired")}}
		_, err := NewUserInfoClient(conn, nil).GetUserInfo(context.Background())
		var authErr *axiam.AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *AuthError, got %T: %v", err, err)
		}
		if conn.calls != 1 {
			t.Fatalf("expected exactly 1 RPC with a nil refresh, got %d", conn.calls)
		}
	})
}

// TestUserInfoClient_PermissionDeniedIsAuthzError proves a terminal
// PERMISSION_DENIED maps through the shared §2 helper to AuthzError.
func TestUserInfoClient_PermissionDeniedIsAuthzError(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.PermissionDenied, "forbidden")}}
	_, err := NewUserInfoClient(conn, nil).GetUserInfo(context.Background())
	var authzErr *axiam.AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T: %v", err, err)
	}
}
