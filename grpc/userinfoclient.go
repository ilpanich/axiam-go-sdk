package grpc

import (
	"context"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// UserInfo is the typed OIDC-style claim set returned by GetUserInfo
// (CONTRACT.md §1.1). Sub, TenantID, and OrgID are always populated; Email is
// non-nil only when the access token carries the "email" scope and
// PreferredUsername only with the "profile" scope. The two optional claims are
// modeled as *string (nil == absent), mirroring how the generated axiam.v1
// gRPC messages model their own `optional string` fields (e.g.
// CheckAccessRequest.Scope).
type UserInfo struct {
	Sub               string
	TenantID          string
	OrgID             string
	Email             *string
	PreferredUsername *string
}

// UserInfoClient is a typed wrapper over the committed axiam.v1
// UserInfoServiceClient stub, exposing GetUserInfo (CONTRACT.md §1/§1.1) with
// §2 gRPC status mapping and a single-flight-refresh retry on UNAUTHENTICATED —
// exactly mirroring AuthzClient.CheckAccess.
type UserInfoClient struct {
	inner   axiamv1.UserInfoServiceClient
	refresh RefreshFunc
}

// NewUserInfoClient wraps conn (built via NewGRPCClient, already carrying the
// same auth/tenant interceptor as the AuthzClient) with the committed
// UserInfoServiceClient stub. refresh drives the shared single-flight refresh
// (§9) on UNAUTHENTICATED; it may be nil, in which case UNAUTHENTICATED errors
// are returned immediately without a retry.
func NewUserInfoClient(conn grpclib.ClientConnInterface, refresh RefreshFunc) *UserInfoClient {
	return &UserInfoClient{
		inner:   axiamv1.NewUserInfoServiceClient(conn),
		refresh: refresh,
	}
}

// GetUserInfo returns the authenticated caller's identity claims
// (CONTRACT.md §1.1) by invoking axiam.v1.UserInfoService/GetUserInfo on the
// SDK's existing gRPC channel. The request is empty — identity is derived
// server-side from the bearer token carried by the shared interceptor. On
// UNAUTHENTICATED, drives the caller-supplied single-flight refresh (§9) and
// retries exactly once — never a second time (§9.3).
func (c *UserInfoClient) GetUserInfo(ctx context.Context) (UserInfo, error) {
	req := &axiamv1.GetUserInfoRequest{}

	resp, err := c.inner.GetUserInfo(ctx, req)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return UserInfo{}, refreshErr
			}
			resp, err = c.inner.GetUserInfo(ctx, req)
		}
		if err != nil {
			return UserInfo{}, mapGRPCError(err)
		}
	}
	return userInfoFromWire(resp), nil
}

// userInfoFromWire maps a GetUserInfoResponse to the typed UserInfo, preserving
// the present/absent distinction of the two scope-gated optional claims (a nil
// wire pointer stays nil in UserInfo).
func userInfoFromWire(resp *axiamv1.GetUserInfoResponse) UserInfo {
	return UserInfo{
		Sub:               resp.GetSub(),
		TenantID:          resp.GetTenantId(),
		OrgID:             resp.GetOrgId(),
		Email:             resp.Email,
		PreferredUsername: resp.PreferredUsername,
	}
}
