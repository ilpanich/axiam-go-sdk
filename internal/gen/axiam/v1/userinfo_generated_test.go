package axiamv1

import (
	"context"
	"errors"
	"testing"

	grpc "google.golang.org/grpc"
)

// These tests mirror the per-service coverage in generated_test.go for the
// UserInfoService stubs added in contract 1.3 (CONTRACT.md §1.1): message wire
// round-trips (including the two scope-gated optional claims), the generated
// client stub forwarding through ClientConnInterface.Invoke, the server handler
// dispatch, the Unimplemented fallback, and ServiceDesc registration. They reuse
// the roundTrip/recordingConn/decodeInto helpers from generated_test.go and, per
// CONTRACT.md §6, use no insecure transport.

func TestUserInfoMessages_RoundTrip(t *testing.T) {
	// Empty request round-trips cleanly.
	_ = roundTrip(t, &GetUserInfoRequest{}, &GetUserInfoRequest{})

	email := "user@example.test"
	preferred := "alice"
	full := roundTrip(t, &GetUserInfoResponse{
		Sub: "sub-1", TenantId: "ten-1", OrgId: "org-1",
		Email: &email, PreferredUsername: &preferred,
	}, &GetUserInfoResponse{})
	if full.GetSub() != "sub-1" || full.GetTenantId() != "ten-1" || full.GetOrgId() != "org-1" {
		t.Fatalf("required userinfo claims not preserved: %+v", full)
	}
	if full.GetEmail() != "user@example.test" || full.GetPreferredUsername() != "alice" {
		t.Fatalf("optional userinfo claims not preserved: %+v", full)
	}

	// Absent optionals must read back as nil pointers / zero-value accessors.
	bare := roundTrip(t, &GetUserInfoResponse{Sub: "sub-2", TenantId: "t", OrgId: "o"}, &GetUserInfoResponse{})
	if bare.Email != nil || bare.PreferredUsername != nil {
		t.Fatalf("expected nil optional claims, got email=%v preferred=%v", bare.Email, bare.PreferredUsername)
	}
	if bare.GetEmail() != "" || bare.GetPreferredUsername() != "" {
		t.Fatalf("unset optional accessors must return zero values: %+v", bare)
	}

	// Nil-safe accessors must not panic.
	var nilResp *GetUserInfoResponse
	if nilResp.GetSub() != "" || nilResp.GetEmail() != "" {
		t.Fatal("nil GetUserInfoResponse accessors must return zero values")
	}
}

func TestUserInfoServiceClient_Stubs(t *testing.T) {
	email := "u@example.test"
	conn := &recordingConn{reply: &GetUserInfoResponse{Sub: "sub", TenantId: "t", OrgId: "o", Email: &email}}
	cli := NewUserInfoServiceClient(conn)

	resp, err := cli.GetUserInfo(context.Background(), &GetUserInfoRequest{})
	if err != nil {
		t.Fatalf("GetUserInfo stub: %v", err)
	}
	if resp.GetSub() != "sub" || resp.GetEmail() != "u@example.test" {
		t.Fatalf("stub did not return the canned reply: %+v", resp)
	}
	if conn.lastMethod != UserInfoService_GetUserInfo_FullMethodName {
		t.Fatalf("stub invoked wrong method: %q", conn.lastMethod)
	}

	// Transport error must propagate unwrapped through the stub.
	errConn := &recordingConn{err: errors.New("boom")}
	if _, err := NewUserInfoServiceClient(errConn).GetUserInfo(context.Background(), &GetUserInfoRequest{}); err == nil {
		t.Fatal("expected the transport error to propagate")
	}
}

type fakeUserInfoServer struct {
	UnimplementedUserInfoServiceServer
}

func (fakeUserInfoServer) GetUserInfo(context.Context, *GetUserInfoRequest) (*GetUserInfoResponse, error) {
	return &GetUserInfoResponse{Sub: "sub"}, nil
}

func TestUserInfoServiceHandlerAndUnimplemented(t *testing.T) {
	// Handler dispatch to the registered impl.
	out, err := _UserInfoService_GetUserInfo_Handler(fakeUserInfoServer{}, context.Background(),
		decodeInto(&GetUserInfoRequest{}), nil)
	if err != nil || out.(*GetUserInfoResponse).GetSub() != "sub" {
		t.Fatalf("GetUserInfo handler: out=%v err=%v", out, err)
	}

	// Unimplemented fallback must error.
	if _, err := (UnimplementedUserInfoServiceServer{}).GetUserInfo(context.Background(), nil); err == nil {
		t.Fatal("Unimplemented GetUserInfo must error")
	}
}

func TestRegisterUserInfoService(t *testing.T) {
	s := grpc.NewServer()
	RegisterUserInfoServiceServer(s, fakeUserInfoServer{})
	if _, ok := s.GetServiceInfo()["axiam.v1.UserInfoService"]; !ok {
		t.Fatal("axiam.v1.UserInfoService was not registered")
	}
	s.Stop()
}
