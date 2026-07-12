package axiam

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestWithLogger_LogfEmitsThroughSink(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	c, err := NewClient("https://example.test", "acme", WithLogger(logger))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.logf(context.Background(), "hello", "key", "value")
	if !strings.Contains(buf.String(), "hello") || !strings.Contains(buf.String(), "value") {
		t.Fatalf("expected the log line to reach the sink, got %q", buf.String())
	}
}

func TestLogf_NilLoggerIsNoop(t *testing.T) {
	c, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Must not panic with the default (nil) logger.
	c.logf(context.Background(), "nothing happens", "k", "v")
}

// TestLogf_SensitiveArgIsRedacted proves CF-02: a Sensitive value passed as a
// log argument never reaches the sink in the clear.
func TestLogf_SensitiveArgIsRedacted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c, err := NewClient("https://example.test", "acme", WithLogger(logger))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.logf(context.Background(), "token issued", "token", Sensitive("super-secret-token"))
	if strings.Contains(buf.String(), "super-secret-token") {
		t.Fatalf("Sensitive value leaked into the log: %q", buf.String())
	}
}

func TestResolvedOrgID(t *testing.T) {
	t.Run("configured WithOrgID wins", func(t *testing.T) {
		id := uuid.MustParse("88888888-8888-8888-8888-888888888888")
		c, err := NewClient("https://example.test", "acme", WithOrgID(id))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		got, ok := c.resolvedOrgID()
		if !ok || got != id {
			t.Fatalf("expected the configured org id, got %v ok=%v", got, ok)
		}
	})
	t.Run("unset then resolved from claim", func(t *testing.T) {
		c, err := NewClient("https://example.test", "acme")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, ok := c.resolvedOrgID(); ok {
			t.Fatal("expected no org id before login")
		}
		resolved := uuid.MustParse("99999999-9999-9999-9999-999999999999")
		c.setResolvedOrgID(resolved)
		got, ok := c.resolvedOrgID()
		if !ok || got != resolved {
			t.Fatalf("expected the resolved org id, got %v ok=%v", got, ok)
		}
	})
}

// TestDoRequest_TransportFailureIsNetworkError proves a transport-level failure
// (server gone) surfaces as a *NetworkError, not a panic or a nil response.
func TestDoRequest_TransportFailureIsNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close() // make the endpoint unreachable

	c, err := NewClient(url, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, _, err = c.CheckAccess(context.Background(), "read", "r-1")
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError on a dead endpoint, got %T: %v", err, err)
	}
}
