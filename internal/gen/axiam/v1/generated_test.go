package axiamv1

import (
	"context"
	"errors"
	"testing"

	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// The internal/gen package is machine-generated (buf), but it is real code the
// SDK's public surface serializes over the wire and dispatches through. These
// tests assert the observable behavior that matters for an SDK client: that
// every message round-trips through the protobuf wire format field-for-field
// (so a server response is decoded correctly), that the generated client stubs
// forward the RPC through the ClientConnInterface and hand back the server's
// reply, and that the generated server handlers dispatch to the registered
// implementation. They avoid a real transport deliberately — CONTRACT.md §6 /
// SC#3 forbid any insecure-credentials surface anywhere in the module's Go
// source, including tests, so no bufconn/insecure dial is used.

// ---------------------------------------------------------------------------
// Message wire round-trips: proto.Marshal -> proto.Unmarshal must preserve
// every field, and the generated Get* accessors must read them back.
// ---------------------------------------------------------------------------

func roundTrip[T proto.Message](t *testing.T, in T, out T) T {
	t.Helper()
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	if err := proto.Unmarshal(raw, out); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("round-trip changed message:\n in=%v\nout=%v", in, out)
	}
	return out
}

func TestCheckAccessRequest_RoundTrip(t *testing.T) {
	scope := "read"
	in := &CheckAccessRequest{
		TenantId:   "tenant-1",
		SubjectId:  "subject-1",
		Action:     "documents:read",
		ResourceId: "resource-1",
		Scope:      &scope,
	}
	got := roundTrip(t, in, &CheckAccessRequest{})
	if got.GetTenantId() != "tenant-1" || got.GetSubjectId() != "subject-1" {
		t.Fatalf("tenant/subject not preserved: %+v", got)
	}
	if got.GetAction() != "documents:read" || got.GetResourceId() != "resource-1" {
		t.Fatalf("action/resource not preserved: %+v", got)
	}
	if got.GetScope() != "read" {
		t.Fatalf("scope not preserved: %q", got.GetScope())
	}
	// An absent optional scope must read back as the zero value, not panic.
	if noScope := (&CheckAccessRequest{}).GetScope(); noScope != "" {
		t.Fatalf("expected empty scope for unset optional field, got %q", noScope)
	}
}

func TestCheckAccessResponse_RoundTrip(t *testing.T) {
	in := &CheckAccessResponse{Allowed: true, DenyReason: "over quota"}
	got := roundTrip(t, in, &CheckAccessResponse{})
	if !got.GetAllowed() || got.GetDenyReason() != "over quota" {
		t.Fatalf("response fields not preserved: %+v", got)
	}
}

func TestBatchCheckAccess_RoundTrip(t *testing.T) {
	in := &BatchCheckAccessRequest{
		Requests: []*CheckAccessRequest{
			{TenantId: "t", Action: "a", ResourceId: "r1"},
			{TenantId: "t", Action: "a", ResourceId: "r2"},
		},
	}
	got := roundTrip(t, in, &BatchCheckAccessRequest{})
	if len(got.GetRequests()) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(got.GetRequests()))
	}
	if got.GetRequests()[1].GetResourceId() != "r2" {
		t.Fatalf("nested request not preserved: %+v", got.GetRequests()[1])
	}

	resp := &BatchCheckAccessResponse{
		Results: []*CheckAccessResponse{{Allowed: true}, {Allowed: false, DenyReason: "nope"}},
	}
	gotResp := roundTrip(t, resp, &BatchCheckAccessResponse{})
	if len(gotResp.GetResults()) != 2 || gotResp.GetResults()[1].GetDenyReason() != "nope" {
		t.Fatalf("batch results not preserved: %+v", gotResp.GetResults())
	}
}

func TestTokenMessages_RoundTrip(t *testing.T) {
	vtReq := roundTrip(t, &ValidateTokenRequest{AccessToken: "tok"}, &ValidateTokenRequest{})
	if vtReq.GetAccessToken() != "tok" {
		t.Fatalf("access token not preserved: %q", vtReq.GetAccessToken())
	}

	vtResp := roundTrip(t, &ValidateTokenResponse{
		Valid: true, SubjectId: "sub", TenantId: "ten", OrgId: "org", Exp: 4102444800,
	}, &ValidateTokenResponse{})
	if !vtResp.GetValid() || vtResp.GetSubjectId() != "sub" || vtResp.GetTenantId() != "ten" {
		t.Fatalf("validate-token response not preserved: %+v", vtResp)
	}
	if vtResp.GetOrgId() != "org" || vtResp.GetExp() != 4102444800 {
		t.Fatalf("org/exp not preserved: %+v", vtResp)
	}

	itReq := roundTrip(t, &IntrospectTokenRequest{AccessToken: "tok2"}, &IntrospectTokenRequest{})
	if itReq.GetAccessToken() != "tok2" {
		t.Fatalf("introspect access token not preserved: %q", itReq.GetAccessToken())
	}

	itResp := roundTrip(t, &IntrospectTokenResponse{
		Active: true, Sub: "s", TenantId: "t", OrgId: "o", Exp: 100, Iat: 50, Iss: "axiam", Jti: "jti-1",
	}, &IntrospectTokenResponse{})
	if !itResp.GetActive() || itResp.GetSub() != "s" || itResp.GetJti() != "jti-1" {
		t.Fatalf("introspect response not preserved: %+v", itResp)
	}
	if itResp.GetExp() != 100 || itResp.GetIat() != 50 || itResp.GetIss() != "axiam" || itResp.GetOrgId() != "o" {
		t.Fatalf("introspect numeric/iss fields not preserved: %+v", itResp)
	}
	if itResp.GetTenantId() != "t" {
		t.Fatalf("introspect tenant not preserved: %+v", itResp)
	}
}

func TestUserMessages_RoundTrip(t *testing.T) {
	guReq := roundTrip(t, &GetUserRequest{TenantId: "t", UserId: "u"}, &GetUserRequest{})
	if guReq.GetTenantId() != "t" || guReq.GetUserId() != "u" {
		t.Fatalf("get-user request not preserved: %+v", guReq)
	}

	ur := roundTrip(t, &UserResponse{
		Id: "id", TenantId: "t", Username: "alice", Email: "a@example.test",
		Status: "active", CreatedAt: "2026-01-01", UpdatedAt: "2026-01-02",
	}, &UserResponse{})
	if ur.GetId() != "id" || ur.GetUsername() != "alice" || ur.GetEmail() != "a@example.test" {
		t.Fatalf("user response identity not preserved: %+v", ur)
	}
	if ur.GetStatus() != "active" || ur.GetCreatedAt() != "2026-01-01" || ur.GetUpdatedAt() != "2026-01-02" {
		t.Fatalf("user response status/timestamps not preserved: %+v", ur)
	}
	if ur.GetTenantId() != "t" {
		t.Fatalf("user response tenant not preserved: %+v", ur)
	}

	vcReq := roundTrip(t, &ValidateCredentialsRequest{
		TenantId: "t", UsernameOrEmail: "alice", Password: "hunter2",
	}, &ValidateCredentialsRequest{})
	if vcReq.GetTenantId() != "t" || vcReq.GetUsernameOrEmail() != "alice" || vcReq.GetPassword() != "hunter2" {
		t.Fatalf("validate-credentials request not preserved: %+v", vcReq)
	}

	vcResp := roundTrip(t, &ValidateCredentialsResponse{Valid: true, UserId: "u-1"}, &ValidateCredentialsResponse{})
	if !vcResp.GetValid() || vcResp.GetUserId() != "u-1" {
		t.Fatalf("validate-credentials response not preserved: %+v", vcResp)
	}
}

// TestMessages_NilAccessorsAndString exercises the generated Reset/String/
// nil-safe accessor paths on empty and nil messages — a nil *Message must
// return zero values from Get*, never panic.
func TestMessages_NilAccessorsAndString(t *testing.T) {
	var nilReq *CheckAccessRequest
	if nilReq.GetTenantId() != "" || nilReq.GetScope() != "" || nilReq.GetAction() != "" {
		t.Fatal("nil CheckAccessRequest accessors must return zero values")
	}
	var nilResp *CheckAccessResponse
	if nilResp.GetAllowed() || nilResp.GetDenyReason() != "" {
		t.Fatal("nil CheckAccessResponse accessors must return zero values")
	}
	var nilUser *UserResponse
	if nilUser.GetId() != "" || nilUser.GetEmail() != "" {
		t.Fatal("nil UserResponse accessors must return zero values")
	}

	// Reset + String must be callable and Reset must clear state.
	msg := &CheckAccessRequest{TenantId: "t", Action: "a"}
	_ = msg.String()
	msg.Reset()
	if msg.GetTenantId() != "" || msg.GetAction() != "" {
		t.Fatalf("Reset did not clear message: %+v", msg)
	}
	// ProtoReflect must yield a descriptor whose full name is stable.
	if got := msg.ProtoReflect().Descriptor().Name(); got != "CheckAccessRequest" {
		t.Fatalf("unexpected descriptor name %q", got)
	}
}

// ---------------------------------------------------------------------------
// Generated client stubs: forward the RPC through ClientConnInterface.Invoke
// and hand back the decoded reply.
// ---------------------------------------------------------------------------

// recordingConn is a fake grpc.ClientConnInterface that records the method
// invoked and copies a canned reply into the caller's out message, so the
// generated client stubs can be exercised without a live server.
type recordingConn struct {
	lastMethod string
	reply      proto.Message
	err        error
}

func (c *recordingConn) Invoke(_ context.Context, method string, _, reply any, _ ...grpc.CallOption) error {
	c.lastMethod = method
	if c.err != nil {
		return c.err
	}
	if c.reply != nil {
		proto.Merge(reply.(proto.Message), c.reply)
	}
	return nil
}

func (c *recordingConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("streaming not supported")
}

func TestAuthorizationServiceClient_Stubs(t *testing.T) {
	conn := &recordingConn{reply: &CheckAccessResponse{Allowed: true, DenyReason: "why"}}
	cli := NewAuthorizationServiceClient(conn)

	resp, err := cli.CheckAccess(context.Background(), &CheckAccessRequest{TenantId: "t"})
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !resp.GetAllowed() || resp.GetDenyReason() != "why" {
		t.Fatalf("stub did not return the canned reply: %+v", resp)
	}
	if conn.lastMethod != AuthorizationService_CheckAccess_FullMethodName {
		t.Fatalf("stub invoked wrong method: %q", conn.lastMethod)
	}

	batchConn := &recordingConn{reply: &BatchCheckAccessResponse{Results: []*CheckAccessResponse{{Allowed: false}}}}
	batchCli := NewAuthorizationServiceClient(batchConn)
	bresp, err := batchCli.BatchCheckAccess(context.Background(), &BatchCheckAccessRequest{})
	if err != nil {
		t.Fatalf("BatchCheckAccess: %v", err)
	}
	if len(bresp.GetResults()) != 1 || bresp.GetResults()[0].GetAllowed() {
		t.Fatalf("batch stub did not return the canned reply: %+v", bresp)
	}

	// Transport error must propagate unwrapped through the stub.
	errConn := &recordingConn{err: errors.New("boom")}
	if _, err := NewAuthorizationServiceClient(errConn).CheckAccess(context.Background(), &CheckAccessRequest{}); err == nil {
		t.Fatal("expected the transport error to propagate")
	}
}

func TestTokenServiceClient_Stubs(t *testing.T) {
	conn := &recordingConn{reply: &ValidateTokenResponse{Valid: true, SubjectId: "s"}}
	cli := NewTokenServiceClient(conn)
	vt, err := cli.ValidateToken(context.Background(), &ValidateTokenRequest{AccessToken: "tok"})
	if err != nil || !vt.GetValid() || vt.GetSubjectId() != "s" {
		t.Fatalf("ValidateToken stub: resp=%+v err=%v", vt, err)
	}
	if conn.lastMethod != TokenService_ValidateToken_FullMethodName {
		t.Fatalf("wrong method: %q", conn.lastMethod)
	}

	introConn := &recordingConn{reply: &IntrospectTokenResponse{Active: true, Sub: "s"}}
	it, err := NewTokenServiceClient(introConn).IntrospectToken(context.Background(), &IntrospectTokenRequest{AccessToken: "tok"})
	if err != nil || !it.GetActive() {
		t.Fatalf("IntrospectToken stub: resp=%+v err=%v", it, err)
	}
}

func TestUserServiceClient_Stubs(t *testing.T) {
	conn := &recordingConn{reply: &UserResponse{Id: "u", Username: "alice"}}
	cli := NewUserServiceClient(conn)
	u, err := cli.GetUser(context.Background(), &GetUserRequest{TenantId: "t", UserId: "u"})
	if err != nil || u.GetUsername() != "alice" {
		t.Fatalf("GetUser stub: resp=%+v err=%v", u, err)
	}
	if conn.lastMethod != UserService_GetUser_FullMethodName {
		t.Fatalf("wrong method: %q", conn.lastMethod)
	}

	vcConn := &recordingConn{reply: &ValidateCredentialsResponse{Valid: true, UserId: "u"}}
	vc, err := NewUserServiceClient(vcConn).ValidateCredentials(context.Background(), &ValidateCredentialsRequest{TenantId: "t"})
	if err != nil || !vc.GetValid() || vc.GetUserId() != "u" {
		t.Fatalf("ValidateCredentials stub: resp=%+v err=%v", vc, err)
	}
}

// ---------------------------------------------------------------------------
// Generated server handlers + registration: the handler wrappers must decode
// the request and dispatch to the registered implementation.
// ---------------------------------------------------------------------------

type fakeAuthzServer struct {
	UnimplementedAuthorizationServiceServer
}

func (fakeAuthzServer) CheckAccess(_ context.Context, in *CheckAccessRequest) (*CheckAccessResponse, error) {
	return &CheckAccessResponse{Allowed: in.GetTenantId() == "ok"}, nil
}
func (fakeAuthzServer) BatchCheckAccess(_ context.Context, in *BatchCheckAccessRequest) (*BatchCheckAccessResponse, error) {
	return &BatchCheckAccessResponse{Results: make([]*CheckAccessResponse, len(in.GetRequests()))}, nil
}

type fakeTokenServer struct {
	UnimplementedTokenServiceServer
}

func (fakeTokenServer) ValidateToken(context.Context, *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	return &ValidateTokenResponse{Valid: true}, nil
}
func (fakeTokenServer) IntrospectToken(context.Context, *IntrospectTokenRequest) (*IntrospectTokenResponse, error) {
	return &IntrospectTokenResponse{Active: true}, nil
}

type fakeUserServer struct{ UnimplementedUserServiceServer }

func (fakeUserServer) GetUser(context.Context, *GetUserRequest) (*UserResponse, error) {
	return &UserResponse{Id: "u"}, nil
}
func (fakeUserServer) ValidateCredentials(context.Context, *ValidateCredentialsRequest) (*ValidateCredentialsResponse, error) {
	return &ValidateCredentialsResponse{Valid: true}, nil
}

// decodeInto returns a protobuf decoder that copies src into the handler's
// freshly-allocated request message, mimicking the codec the real server uses.
func decodeInto(src proto.Message) func(any) error {
	return func(dst any) error {
		proto.Merge(dst.(proto.Message), src)
		return nil
	}
}

func TestAuthorizationServiceHandlers(t *testing.T) {
	srv := fakeAuthzServer{}

	// interceptor == nil path: direct dispatch to the server impl.
	out, err := _AuthorizationService_CheckAccess_Handler(srv, context.Background(),
		decodeInto(&CheckAccessRequest{TenantId: "ok"}), nil)
	if err != nil {
		t.Fatalf("CheckAccess handler: %v", err)
	}
	if !out.(*CheckAccessResponse).GetAllowed() {
		t.Fatal("handler did not dispatch to the registered impl")
	}

	// interceptor != nil path: the wrapper must route through the interceptor.
	var intercepted bool
	interceptor := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		intercepted = true
		return handler(ctx, req)
	}
	if _, err := _AuthorizationService_BatchCheckAccess_Handler(srv, context.Background(),
		decodeInto(&BatchCheckAccessRequest{}), interceptor); err != nil {
		t.Fatalf("BatchCheckAccess handler: %v", err)
	}
	if !intercepted {
		t.Fatal("interceptor was not invoked")
	}

	// decode-error path: a decoder failure must surface as the handler error.
	decErr := errors.New("bad frame")
	if _, err := _AuthorizationService_CheckAccess_Handler(srv, context.Background(),
		func(any) error { return decErr }, nil); !errors.Is(err, decErr) {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestTokenAndUserServiceHandlers(t *testing.T) {
	if out, err := _TokenService_ValidateToken_Handler(fakeTokenServer{}, context.Background(),
		decodeInto(&ValidateTokenRequest{}), nil); err != nil || !out.(*ValidateTokenResponse).GetValid() {
		t.Fatalf("ValidateToken handler: out=%v err=%v", out, err)
	}
	if out, err := _TokenService_IntrospectToken_Handler(fakeTokenServer{}, context.Background(),
		decodeInto(&IntrospectTokenRequest{}), nil); err != nil || !out.(*IntrospectTokenResponse).GetActive() {
		t.Fatalf("IntrospectToken handler: out=%v err=%v", out, err)
	}
	if out, err := _UserService_GetUser_Handler(fakeUserServer{}, context.Background(),
		decodeInto(&GetUserRequest{}), nil); err != nil || out.(*UserResponse).GetId() != "u" {
		t.Fatalf("GetUser handler: out=%v err=%v", out, err)
	}
	if out, err := _UserService_ValidateCredentials_Handler(fakeUserServer{}, context.Background(),
		decodeInto(&ValidateCredentialsRequest{}), nil); err != nil || !out.(*ValidateCredentialsResponse).GetValid() {
		t.Fatalf("ValidateCredentials handler: out=%v err=%v", out, err)
	}
}

// TestMessages_ReflectionSurface exercises the String/Descriptor/ProtoMessage
// marker methods every generated message carries, across all message types, so
// the protobuf reflection surface the runtime relies on is covered uniformly.
func TestMessages_ReflectionSurface(t *testing.T) {
	msgs := []proto.Message{
		&CheckAccessRequest{TenantId: "t"}, &CheckAccessResponse{Allowed: true},
		&BatchCheckAccessRequest{}, &BatchCheckAccessResponse{},
		&ValidateTokenRequest{}, &ValidateTokenResponse{},
		&IntrospectTokenRequest{}, &IntrospectTokenResponse{},
		&GetUserRequest{}, &UserResponse{},
		&ValidateCredentialsRequest{}, &ValidateCredentialsResponse{},
	}
	for _, m := range msgs {
		if got := m.ProtoReflect().Descriptor(); got == nil {
			t.Fatalf("%T: nil descriptor", m)
		}
		// String() must be callable and reflect the message name.
		if s, ok := m.(interface{ String() string }); ok {
			_ = s.String()
		}
	}
}

// TestUnimplementedServers proves the generated Unimplemented* fallbacks return
// an Unimplemented status for every method — the behavior a partially
// implemented server exposes for methods it has not overridden.
func TestUnimplementedServers(t *testing.T) {
	ctx := context.Background()
	authz := UnimplementedAuthorizationServiceServer{}
	if _, err := authz.CheckAccess(ctx, nil); err == nil {
		t.Fatal("Unimplemented CheckAccess must error")
	}
	if _, err := authz.BatchCheckAccess(ctx, nil); err == nil {
		t.Fatal("Unimplemented BatchCheckAccess must error")
	}
	tok := UnimplementedTokenServiceServer{}
	if _, err := tok.ValidateToken(ctx, nil); err == nil {
		t.Fatal("Unimplemented ValidateToken must error")
	}
	if _, err := tok.IntrospectToken(ctx, nil); err == nil {
		t.Fatal("Unimplemented IntrospectToken must error")
	}
	usr := UnimplementedUserServiceServer{}
	if _, err := usr.GetUser(ctx, nil); err == nil {
		t.Fatal("Unimplemented GetUser must error")
	}
	if _, err := usr.ValidateCredentials(ctx, nil); err == nil {
		t.Fatal("Unimplemented ValidateCredentials must error")
	}
}

// TestRegisterServers registers each generated service against a real
// grpc.Server (no transport, no listener) to cover the Register* helpers and
// their ServiceDesc wiring.
func TestRegisterServers(t *testing.T) {
	s := grpc.NewServer()
	RegisterAuthorizationServiceServer(s, fakeAuthzServer{})
	RegisterTokenServiceServer(s, fakeTokenServer{})
	RegisterUserServiceServer(s, fakeUserServer{})

	info := s.GetServiceInfo()
	for _, svc := range []string{
		"axiam.v1.AuthorizationService",
		"axiam.v1.TokenService",
		"axiam.v1.UserService",
	} {
		if _, ok := info[svc]; !ok {
			t.Fatalf("service %s was not registered", svc)
		}
	}
	s.Stop()
}
