package axiamv1

import (
	"context"
	"errors"
	"testing"

	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// The tests here complete coverage of the generated accessor and descriptor
// surface that the round-trip tests do not exercise: the nil-receiver fallback
// branch of every Get* accessor (a typed-nil *Message must return the zero
// value, never panic), the deprecated Descriptor() byte/index accessor on every
// message, and the ProtoMessage() marker method. These are the paths the
// protobuf runtime and any reflective caller depend on.

// TestNilGetters_AllMessages calls every generated accessor on a typed-nil
// pointer. Each accessor's `if x != nil` guard must take the false branch and
// hand back the zero value.
func TestNilGetters_AllMessages(t *testing.T) {
	t.Run("CheckAccessRequest", func(t *testing.T) {
		var x *CheckAccessRequest
		if x.GetTenantId() != "" || x.GetSubjectId() != "" || x.GetAction() != "" ||
			x.GetResourceId() != "" || x.GetScope() != "" {
			t.Fatal("nil CheckAccessRequest getters must be zero")
		}
	})
	t.Run("CheckAccessResponse", func(t *testing.T) {
		var x *CheckAccessResponse
		if x.GetAllowed() || x.GetDenyReason() != "" {
			t.Fatal("nil CheckAccessResponse getters must be zero")
		}
	})
	t.Run("BatchCheckAccessRequest", func(t *testing.T) {
		var x *BatchCheckAccessRequest
		if x.GetRequests() != nil {
			t.Fatal("nil BatchCheckAccessRequest.GetRequests must be nil")
		}
	})
	t.Run("BatchCheckAccessResponse", func(t *testing.T) {
		var x *BatchCheckAccessResponse
		if x.GetResults() != nil {
			t.Fatal("nil BatchCheckAccessResponse.GetResults must be nil")
		}
	})
	t.Run("ValidateTokenRequest", func(t *testing.T) {
		var x *ValidateTokenRequest
		if x.GetAccessToken() != "" {
			t.Fatal("nil ValidateTokenRequest.GetAccessToken must be empty")
		}
	})
	t.Run("ValidateTokenResponse", func(t *testing.T) {
		var x *ValidateTokenResponse
		if x.GetValid() || x.GetSubjectId() != "" || x.GetTenantId() != "" ||
			x.GetOrgId() != "" || x.GetExp() != 0 {
			t.Fatal("nil ValidateTokenResponse getters must be zero")
		}
	})
	t.Run("IntrospectTokenRequest", func(t *testing.T) {
		var x *IntrospectTokenRequest
		if x.GetAccessToken() != "" {
			t.Fatal("nil IntrospectTokenRequest.GetAccessToken must be empty")
		}
	})
	t.Run("IntrospectTokenResponse", func(t *testing.T) {
		var x *IntrospectTokenResponse
		if x.GetActive() || x.GetSub() != "" || x.GetTenantId() != "" || x.GetOrgId() != "" ||
			x.GetIss() != "" || x.GetIat() != 0 || x.GetExp() != 0 || x.GetJti() != "" {
			t.Fatal("nil IntrospectTokenResponse getters must be zero")
		}
	})
	t.Run("GetUserRequest", func(t *testing.T) {
		var x *GetUserRequest
		if x.GetTenantId() != "" || x.GetUserId() != "" {
			t.Fatal("nil GetUserRequest getters must be zero")
		}
	})
	t.Run("UserResponse", func(t *testing.T) {
		var x *UserResponse
		if x.GetId() != "" || x.GetTenantId() != "" || x.GetUsername() != "" || x.GetEmail() != "" ||
			x.GetStatus() != "" || x.GetCreatedAt() != "" || x.GetUpdatedAt() != "" {
			t.Fatal("nil UserResponse getters must be zero")
		}
	})
	t.Run("ValidateCredentialsRequest", func(t *testing.T) {
		var x *ValidateCredentialsRequest
		if x.GetTenantId() != "" || x.GetUsernameOrEmail() != "" || x.GetPassword() != "" {
			t.Fatal("nil ValidateCredentialsRequest getters must be zero")
		}
	})
	t.Run("ValidateCredentialsResponse", func(t *testing.T) {
		var x *ValidateCredentialsResponse
		if x.GetValid() || x.GetUserId() != "" {
			t.Fatal("nil ValidateCredentialsResponse getters must be zero")
		}
	})
}

// descriptorProvider is the deprecated legacy accessor every generated message
// still carries: it returns the gzipped file descriptor and the message's index
// path. Exercising it covers both Descriptor() and the lazily-built
// rawDescGZIP() helper it delegates to.
type descriptorProvider interface {
	proto.Message
	Descriptor() ([]byte, []int)
	ProtoMessage()
}

// TestDescriptorAndProtoMessage_AllMessages calls the deprecated Descriptor()
// accessor and the ProtoMessage() marker on one instance of every generated
// message type.
func TestDescriptorAndProtoMessage_AllMessages(t *testing.T) {
	msgs := []descriptorProvider{
		&CheckAccessRequest{}, &CheckAccessResponse{},
		&BatchCheckAccessRequest{}, &BatchCheckAccessResponse{},
		&ValidateTokenRequest{}, &ValidateTokenResponse{},
		&IntrospectTokenRequest{}, &IntrospectTokenResponse{},
		&GetUserRequest{}, &UserResponse{},
		&ValidateCredentialsRequest{}, &ValidateCredentialsResponse{},
	}
	for _, m := range msgs {
		raw, idx := m.Descriptor()
		if len(raw) == 0 {
			t.Fatalf("%T: Descriptor returned empty gzipped bytes", m)
		}
		if len(idx) == 0 {
			t.Fatalf("%T: Descriptor returned empty index path", m)
		}
		// ProtoMessage is a compile-time marker with no observable result;
		// calling it must not panic.
		m.ProtoMessage()
	}
}

// TestTokenUserStubs_ErrorPropagation covers the `if err != nil` failure branch
// of the token and user client stubs, which the happy-path stub tests skip.
func TestTokenUserStubs_ErrorPropagation(t *testing.T) {
	boom := errors.New("transport down")
	ctx := context.Background()

	if _, err := NewTokenServiceClient(&recordingConn{err: boom}).
		ValidateToken(ctx, &ValidateTokenRequest{}); !errors.Is(err, boom) {
		t.Fatalf("ValidateToken must propagate transport error, got %v", err)
	}
	if _, err := NewTokenServiceClient(&recordingConn{err: boom}).
		IntrospectToken(ctx, &IntrospectTokenRequest{}); !errors.Is(err, boom) {
		t.Fatalf("IntrospectToken must propagate transport error, got %v", err)
	}
	if _, err := NewUserServiceClient(&recordingConn{err: boom}).
		GetUser(ctx, &GetUserRequest{}); !errors.Is(err, boom) {
		t.Fatalf("GetUser must propagate transport error, got %v", err)
	}
	if _, err := NewUserServiceClient(&recordingConn{err: boom}).
		ValidateCredentials(ctx, &ValidateCredentialsRequest{}); !errors.Is(err, boom) {
		t.Fatalf("ValidateCredentials must propagate transport error, got %v", err)
	}
}

// TestTokenUserHandlers_InterceptorAndDecodeError covers, for every token and
// user handler, the two branches the nil-interceptor happy path leaves out: the
// interceptor != nil dispatch and the decode-failure error return.
func TestTokenUserHandlers_InterceptorAndDecodeError(t *testing.T) {
	ctx := context.Background()
	decErr := errors.New("bad frame")
	failDecode := func(any) error { return decErr }

	var intercepted int
	interceptor := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		intercepted++
		return handler(ctx, req)
	}

	type handlerCase struct {
		name    string
		handler func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error)
		good    func(any) error
	}
	cases := []handlerCase{
		{"ValidateToken", _TokenService_ValidateToken_Handler, decodeInto(&ValidateTokenRequest{})},
		{"IntrospectToken", _TokenService_IntrospectToken_Handler, decodeInto(&IntrospectTokenRequest{})},
		{"GetUser", _UserService_GetUser_Handler, decodeInto(&GetUserRequest{})},
		{"ValidateCredentials", _UserService_ValidateCredentials_Handler, decodeInto(&ValidateCredentialsRequest{})},
	}

	srvFor := func(name string) any {
		switch name {
		case "GetUser", "ValidateCredentials":
			return fakeUserServer{}
		default:
			return fakeTokenServer{}
		}
	}

	for _, c := range cases {
		t.Run(c.name+"/interceptor", func(t *testing.T) {
			before := intercepted
			if _, err := c.handler(srvFor(c.name), ctx, c.good, interceptor); err != nil {
				t.Fatalf("%s via interceptor: %v", c.name, err)
			}
			if intercepted != before+1 {
				t.Fatalf("%s interceptor was not invoked", c.name)
			}
		})
		t.Run(c.name+"/decodeError", func(t *testing.T) {
			if _, err := c.handler(srvFor(c.name), ctx, failDecode, nil); !errors.Is(err, decErr) {
				t.Fatalf("%s expected decode error, got %v", c.name, err)
			}
		})
	}
}
