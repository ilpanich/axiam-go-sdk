package axiam

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Targeted coverage for the contract-1.51 manifest/reconciler additions that
// TestManifest_* and TestManifestAdditions_* do not otherwise exercise:
// the builder's resource-scoped/non-inheriting attachment methods for
// groups and service accounts (§27.6.1 items 2-3), ResourceMetadata
// (§27.6.1 item 1), and a handful of small internal helpers the reconciler
// relies on (asNetworkError, containsUUID, rebindFailure.Error,
// metadataStateEqual's cannot-compare branch).

// ---------------------------------------------------------------------------
// ManifestBuilder.GroupRole
// ---------------------------------------------------------------------------

func TestManifestBuilder_GroupRoleAttachesAScopedBindingToTheNamedGroup(t *testing.T) {
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		Permission("read", "document:read", "Read").
		Role("editor", "Editor", "Edits documents").
		Group("staff", "Staff", "Everyone").
		GroupRole("staff", ScopedRole("editor", "docs")).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.Groups) != 1 || len(m.Groups[0].Roles) != 1 {
		t.Fatalf("want exactly one role bound to the one group, got %+v", m.Groups)
	}
	got := m.Groups[0].Roles[0]
	if got.Role != "editor" || got.Resource != "docs" {
		t.Fatalf("want editor@docs, got %+v", got)
	}
}

func TestManifestBuilder_GroupRoleNamingAnUndeclaredGroupIsAForwardReferenceRefusal(t *testing.T) {
	_, err := NewManifest().
		Role("editor", "Editor", "Edits documents").
		GroupRole("staff", RoleKey("editor")).
		Build()
	if err == nil || !strings.Contains(err.Error(), `GroupRole names group "staff", which no Group call has declared yet`) {
		t.Fatalf("want a forward-reference refusal naming GroupRole and the group key, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ManifestBuilder.ServiceAccount / ServiceAccountRole
// ---------------------------------------------------------------------------

func TestManifestBuilder_ServiceAccountDeclaresOneWithNameAndDescription(t *testing.T) {
	m, err := NewManifest().
		ServiceAccount("ci", "ci-bot", "Runs the pipeline").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.ServiceAccounts) != 1 {
		t.Fatalf("want exactly one service account, got %d", len(m.ServiceAccounts))
	}
	sa := m.ServiceAccounts[0]
	if sa.Key != "ci" || sa.Name != "ci-bot" || sa.Description != "Runs the pipeline" {
		t.Fatalf("want ci/ci-bot/Runs the pipeline, got %+v", sa)
	}
}

func TestManifestBuilder_ServiceAccountRoleAttachesANonInheritingBindingToTheNamedAccount(t *testing.T) {
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		Permission("read", "document:read", "Read").
		Role("editor", "Editor", "Edits documents").
		ServiceAccount("ci", "ci-bot", "").
		ServiceAccountRole("ci", NonInheritedRole("editor", "docs")).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.ServiceAccounts) != 1 || len(m.ServiceAccounts[0].Roles) != 1 {
		t.Fatalf("want exactly one role bound to the one service account, got %+v", m.ServiceAccounts)
	}
	got := m.ServiceAccounts[0].Roles[0]
	if got.Role != "editor" || got.Resource != "docs" || !got.NoInherit {
		t.Fatalf("want a non-inheriting editor@docs binding, got %+v", got)
	}
}

func TestManifestBuilder_ServiceAccountRoleNamingAnUndeclaredAccountIsAForwardReferenceRefusal(t *testing.T) {
	_, err := NewManifest().
		Role("editor", "Editor", "Edits documents").
		ServiceAccountRole("ci", RoleKey("editor")).
		Build()
	if err == nil || !strings.Contains(err.Error(),
		`ServiceAccountRole names service account "ci", which no ServiceAccount call has declared yet`) {
		t.Fatalf("want a forward-reference refusal naming ServiceAccountRole and the account key, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ManifestBuilder.ResourceMetadata
// ---------------------------------------------------------------------------

func TestManifestBuilder_ResourceMetadataStatesTheMapOnTheNamedResource(t *testing.T) {
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		ResourceMetadata("docs", map[string]any{"owner": "platform-team"}).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("want exactly one resource, got %d", len(m.Resources))
	}
	if got := m.Resources[0].Metadata["owner"]; got != "platform-team" {
		t.Fatalf("want owner=platform-team, got %+v", m.Resources[0].Metadata)
	}
}

func TestManifestBuilder_ResourceMetadataAcceptsAnExplicitlyEmptyMap(t *testing.T) {
	// §27.6.1 item 1: an explicit empty map is a STATED "none", distinct
	// from never calling ResourceMetadata at all (which leaves it unstated).
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		ResourceMetadata("docs", map[string]any{}).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.Resources[0].Metadata == nil || len(m.Resources[0].Metadata) != 0 {
		t.Fatalf("want a stated-but-empty map, got %#v", m.Resources[0].Metadata)
	}
}

func TestManifestBuilder_ResourceMetadataNamingAnUndeclaredResourceIsAForwardReferenceRefusal(t *testing.T) {
	_, err := NewManifest().
		ResourceMetadata("docs", map[string]any{"owner": "platform-team"}).
		Build()
	if err == nil || !strings.Contains(err.Error(),
		`ResourceMetadata names resource "docs", which no Resource/ChildResource call has declared yet`) {
		t.Fatalf("want a forward-reference refusal naming ResourceMetadata and the resource key, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Small internal helpers the reconciler leans on
// ---------------------------------------------------------------------------

func TestAsNetworkError_TrueForANetworkErrorFalseOtherwise(t *testing.T) {
	var target *NetworkError
	if ok := asNetworkError(&NetworkError{Message: "boom"}, &target); !ok || target == nil || target.Message != "boom" {
		t.Fatalf("want ok with the *NetworkError populated, got ok=%v target=%+v", ok, target)
	}

	target = nil
	if ok := asNetworkError(context.DeadlineExceeded, &target); ok || target != nil {
		t.Fatalf("want false and target left nil for a non-*NetworkError, got ok=%v target=%+v", ok, target)
	}
}

func TestContainsUUID_TrueWhenPresentFalseWhenAbsent(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	c := uuid.New()
	haystack := []uuid.UUID{a, b}

	if !containsUUID(haystack, a) {
		t.Fatalf("want true for a member of the slice")
	}
	if containsUUID(haystack, c) {
		t.Fatalf("want false for a uuid absent from the slice")
	}
	if containsUUID(nil, a) {
		t.Fatalf("want false for a nil slice")
	}
}

func TestRebindFailure_ErrorReturnsTheAssignErrorNotTheRestoreError(t *testing.T) {
	rf := &rebindFailure{
		assignErr:  &NetworkError{Message: "assign failed"},
		restoreErr: &NetworkError{Message: "restore also failed"},
	}
	if got := rf.Error(); got != rf.assignErr.Error() {
		t.Fatalf("want the assign error's own Error() text, got %q", got)
	}
	if strings.Contains(rf.Error(), "restore also failed") {
		t.Fatalf("want the restore error's text absent from rebindFailure.Error(), got %q", rf.Error())
	}
}

// ---------------------------------------------------------------------------
// metadataStateEqual's cannot-compare branch
// ---------------------------------------------------------------------------

func TestMetadataStateEqual_UnmarshalableValueIsTreatedAsDrifted(t *testing.T) {
	// json.Marshal refuses NaN/Inf floats, which is the one realistic way
	// metadataStateEqual's marshal can fail on either side; when it does,
	// the function must report drift (false) rather than panicking or
	// silently reporting equality.
	if metadataStateEqual(map[string]any{"score": math.NaN()}, map[string]any{}) {
		t.Fatalf("want drift reported when the spec side cannot be marshaled")
	}
	if metadataStateEqual(map[string]any{}, map[string]any{"score": math.Inf(1)}) {
		t.Fatalf("want drift reported when the current side cannot be marshaled")
	}
}
