package axiam

import (
	"fmt"

	"github.com/google/uuid"
)

// Where {org_id} and {tenant_id} come from — CONTRACT.md §27.4 rule 3.
//
// Thirty of the 146 routes carry one or both, and in almost every call they
// are the client's own. Making the caller restate them every time is ceremony
// that gets wrapped in a helper anyway; making them impossible to override is
// worse, because a platform-admin token legitimately administers a tenant
// other than the one its client was built with. So they default from the
// client, and every handle that needs one exposes an override.
//
// A note on the §27.9 requirement that "a non-UUID identifier fails
// client-side with zero wire calls": on this surface that is the type system's
// job, not a runtime check. Every {..._id} path parameter is a uuid.UUID, so a
// slug does not compile — which is a stronger guarantee than a validated
// string, and the same one the Rust reference gets.

// namespaceScope holds the per-handle overrides for the two implicit path
// parameters.
//
// Unexported: a caller reaches these through InOrg/ForTenant on a handle,
// which is the only place they can be applied.
type namespaceScope struct {
	orgID    *uuid.UUID
	tenantID *uuid.UUID
}

func (s namespaceScope) withOrg(id uuid.UUID) namespaceScope {
	s.orgID = &id
	return s
}

func (s namespaceScope) withTenant(id uuid.UUID) namespaceScope {
	s.tenantID = &id
	return s
}

// resolveOrg resolves {org_id}: the handle's override, else the client's.
//
// A client built with WithOrgSlug and no WithOrgID that has not yet logged in
// fails HERE, with no wire call. §27.4 rule 3 forbids resolving the slug behind
// the caller's back: a silent extra round-trip on an admin path is what §12.1
// rule 2 refuses for /oauth2/*, and for the same reason — the caller cannot see
// it, cannot cache it, and pays for it on every call.
func (c *Client) resolveOrg(scope namespaceScope, operation string) (uuid.UUID, error) {
	if scope.orgID != nil {
		return *scope.orgID, nil
	}
	if id, ok := c.resolvedOrgID(); ok {
		return id, nil
	}
	return uuid.UUID{}, &NetworkError{Message: fmt.Sprintf(
		"%s: this route needs an organization UUID and the client has none. Construct it "+
			"with WithOrgID, call Login so the access token's org_id claim resolves one, or "+
			"name one on the handle with InOrg.", operation)}
}

// resolveTenant resolves {tenant_id} where it names the *context*, not the
// object.
//
// Namespaces where {tenant_id} names the thing being acted on — Tenants, and
// the signing CAs under CaCertificates — take it as an ordinary argument
// instead and never reach this.
//
// This client is constructed with a tenant SLUG (§5 requires one and there is
// no tenant-UUID constructor argument), so the UUID normally arrives with the
// access token's tenant_id claim. Before a login there is none, and that is a
// client-side failure rather than a request that would 404.
func (c *Client) resolveTenant(scope namespaceScope, operation string) (uuid.UUID, error) {
	if scope.tenantID != nil {
		return *scope.tenantID, nil
	}
	if id, ok := c.resolvedOrgTenantID(); ok {
		return id, nil
	}
	return uuid.UUID{}, &NetworkError{Message: fmt.Sprintf(
		"%s: this route needs a tenant UUID, but the client was built with tenant slug %q "+
			"and none has been resolved yet. Call Login so the access token's tenant_id claim "+
			"resolves one, or name one on the handle with ForTenant.", operation, c.tenantSlug)}
}

// ResolvedTenantID returns the tenant UUID resolved from the access token's
// tenant_id claim, and whether one is available.
//
// The exported twin of ResolvedOrgID, and symmetric with it for the same
// reason: this client is constructed with a tenant slug, so the UUID only
// exists after a login has decoded it. CONTRACT.md §27 routes that name a
// tenant explicitly — the signing CAs under CaCertificates, and the Tenants
// namespace itself — take that UUID as an ordinary argument rather than
// defaulting it (§27.4 rule 3, because there it names the object being acted
// on rather than the context), so a caller outside this package needs a way to
// read the one the session already knows instead of re-deriving it.
func (c *Client) ResolvedTenantID() (uuid.UUID, bool) {
	return c.resolvedOrgTenantID()
}

// ResolvedOrgID returns the organization UUID this client will use, and
// whether one is available: the explicitly configured WithOrgID value if
// present, otherwise the value resolved from the access token's org_id claim
// after a login.
//
// Exported for the same reason as ResolvedTenantID: §27 callers outside this
// package legitimately need to know which organization a management call will
// address before making it.
func (c *Client) ResolvedOrgID() (uuid.UUID, bool) {
	return c.resolvedOrgID()
}
