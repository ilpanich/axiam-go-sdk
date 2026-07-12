package main

import "testing"

func TestGetenv(t *testing.T) {
	t.Setenv("AXIAM_TEST_AMQP_KEY", "from-env")
	if got := getenv("AXIAM_TEST_AMQP_KEY", "fallback"); got != "from-env" {
		t.Fatalf("expected the env value, got %q", got)
	}
	if got := getenv("AXIAM_TEST_AMQP_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("expected the fallback, got %q", got)
	}
}
