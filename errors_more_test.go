package axiam

import "testing"

// TestSanitizeResponse_Nil covers the nil-guard branch of sanitizeResponse: a
// nil response sanitizes to nil rather than panicking.
func TestSanitizeResponse_Nil(t *testing.T) {
	if got := sanitizeResponse(nil); got != nil {
		t.Fatalf("sanitizeResponse(nil) must be nil, got %+v", got)
	}
}
