package axiam

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Reconciling a manifest against a live tenant — CONTRACT.md §27.6.
//
// The split here is deliberate. Everything that DECIDES — matching specs
// against the tenant's current state, ordering the work, resolving manifest
// keys to server ids — is pure and lives in computeSteps, so Plan and Apply
// cannot disagree about what would happen: Apply runs exactly the steps Plan
// reported. Only reading the snapshot and running a step touch the network.

// planPageSize is how many items a planning read asks for per page.
const planPageSize = 200

// ManifestAPI is the declarative-management handle, reached as c.Manifest().
type ManifestAPI struct {
	c *Client
}

// Manifest returns the §27.6 declarative-management handle.
//
// Acquiring it performs no I/O, exactly as the namespace handles do not.
func (c *Client) Manifest() *ManifestAPI { return &ManifestAPI{c: c} }

// resolved holds manifest keys resolved to server ids, filled in during
// planning and completed during applying.
type resolved struct {
	resources       map[string]uuid.UUID
	scopes          map[string]uuid.UUID
	permissions     map[string]uuid.UUID
	roles           map[string]uuid.UUID
	groups          map[string]uuid.UUID
	users           map[string]uuid.UUID
	serviceAccounts map[string]uuid.UUID
}

func newResolved() *resolved {
	return &resolved{
		resources:       map[string]uuid.UUID{},
		scopes:          map[string]uuid.UUID{},
		permissions:     map[string]uuid.UUID{},
		roles:           map[string]uuid.UUID{},
		groups:          map[string]uuid.UUID{},
		users:           map[string]uuid.UUID{},
		serviceAccounts: map[string]uuid.UUID{},
	}
}

// bindingInfo is a role assignment as the server holds it — one entry of a
// roles.list_users/_groups/_service_accounts response — carrying what
// §27.6.1's two-shape reconciliation needs beyond mere presence: the
// resource it is scoped to (nil for a plain, tenant-wide assignment),
// whether it inherits, and the tenant_scope to carry across on a rebind
// (§27.6.1: "An Update's re-assignment MUST carry the server binding's
// existing tenant_scope across unchanged").
type bindingInfo struct {
	subjectID   uuid.UUID
	resourceID  *uuid.UUID
	inherit     bool
	tenantScope []uuid.UUID
}

// sameBinding reports whether spec (a manifest RoleBinding) already
// matches this server-held binding — §27.6.1's natural key is (subject,
// role), with resource and inherit as FIELDS: NoChange when both agree,
// Update (a rebind) otherwise.
func (b bindingInfo) sameBinding(spec RoleBinding, resourceOf func(key string) (uuid.UUID, bool)) bool {
	var wantResource *uuid.UUID
	if spec.Resource != "" {
		if id, ok := resourceOf(spec.Resource); ok {
			wantResource = &id
		} else {
			// The manifest resource has not been resolved (should not
			// happen once resources have been planned) — treat as
			// non-matching so this surfaces as an Update rather than a
			// false NoChange.
			return false
		}
	}
	if !samePointerUUID(b.resourceID, wantResource) {
		return false
	}
	wantInherit := !spec.NoInherit || spec.Resource == ""
	return b.inherit == wantInherit
}

// snapshot is the current tenant state a plan is computed against.
type snapshot struct {
	resources              []Resource
	scopes                 map[uuid.UUID][]Scope
	permissions            []Permission
	roles                  []Role
	groups                 []Group
	users                  []UserResponse
	serviceAccounts        []ServiceAccountResponse
	roleGrants             map[uuid.UUID][]uuid.UUID
	roleUserBindings       map[uuid.UUID][]bindingInfo
	roleGroupBindings      map[uuid.UUID][]bindingInfo
	roleServiceAccountBind map[uuid.UUID][]bindingInfo
	groupMembers           map[uuid.UUID][]uuid.UUID
}

// stepKind names one executable operation.
type stepKind string

const (
	stepNoop                     stepKind = "noop"
	stepCreateResource           stepKind = "create-resource"
	stepUpdateResource           stepKind = "update-resource"
	stepCreateScope              stepKind = "create-scope"
	stepCreatePermission         stepKind = "create-permission"
	stepUpdatePermission         stepKind = "update-permission"
	stepCreateRole               stepKind = "create-role"
	stepUpdateRole               stepKind = "update-role"
	stepGrantPermission          stepKind = "grant-permission"
	stepCreateGroup              stepKind = "create-group"
	stepUpdateGroup              stepKind = "update-group"
	stepBindRoleToGroup          stepKind = "bind-role-to-group"
	stepCreateUser               stepKind = "create-user"
	stepUpdateUser               stepKind = "update-user"
	stepBindRoleToUser           stepKind = "bind-role-to-user"
	stepAddGroupMember           stepKind = "add-group-member"
	stepCreateServiceAccount     stepKind = "create-service-account"
	stepUpdateServiceAccount     stepKind = "update-service-account"
	stepBindRoleToServiceAccount stepKind = "bind-role-to-service-account"
)

// bindingChange is the step.spec payload for stepBindRoleTo{User,Group,
// ServiceAccount} — §27.6.1 item 2's two-shape role binding, carrying
// enough to either CREATE a fresh assignment (previous == nil) or REBIND
// one (previous != nil: unassign previous's exact shape, then assign
// binding — §27.6.1: "An Update is unassign then assign").
type bindingChange struct {
	roleKey    string
	subjectKey string
	binding    RoleBinding
	// previous is nil for a Create. For an Update it is the server's
	// CURRENT binding — resource, inherit and tenant_scope — which run()
	// unassigns first and, if the new assign then fails, re-assigns
	// verbatim (§27.6.1: "the server binding's tenant_scope carried
	// across unchanged").
	previous *bindingInfo
}

// rebindFailure is returned by run() for a failed REBIND (never a plain
// Create) so execute() can emit the two AppliedSteps §27.6.1 requires: the
// failed assign, and the restore attempt's own outcome.
type rebindFailure struct {
	assignErr  error
	restoreErr error // nil: the restore succeeded. non-nil: it also failed.
}

func (r *rebindFailure) Error() string { return r.assignErr.Error() }

// step is one executable step, carrying manifest keys rather than ids.
//
// Ids are deliberately absent: a step that creates a child resource is planned
// before its parent exists, so it can only name the parent by key and resolve
// it when the parent's own step has run.
type step struct {
	kind    stepKind
	key     string
	spec    any
	related string
}

// plannedStep pairs the action a human reads with the step that carries it out.
type plannedStep struct {
	action PlannedAction
	step   step
}

// Plan reports what reconciling the manifest would do. It issues NO writes.
func (a *ManifestAPI) Plan(ctx context.Context, m ManagementManifest) (ManagementPlan, error) {
	if err := validateManifest(m); err != nil {
		return ManagementPlan{}, err
	}
	snap, err := a.read(ctx, m)
	if err != nil {
		return ManagementPlan{}, err
	}
	steps, err := computeSteps(m, snap, newResolved())
	if err != nil {
		return ManagementPlan{}, err
	}
	if err := requirePasswords(steps); err != nil {
		return ManagementPlan{}, err
	}
	plan := ManagementPlan{}
	for _, s := range steps {
		plan.Actions = append(plan.Actions, s.action)
	}
	return plan, nil
}

// Apply reconciles the manifest, stopping at the first failure.
//
// Re-running after fixing the cause is the recovery path, and is safe: applying
// twice converges (§27.6 rule 6).
func (a *ManifestAPI) Apply(ctx context.Context, m ManagementManifest) (ApplyReport, error) {
	if err := validateManifest(m); err != nil {
		return ApplyReport{}, err
	}
	snap, err := a.read(ctx, m)
	if err != nil {
		return ApplyReport{}, err
	}
	res := newResolved()
	steps, err := computeSteps(m, snap, res)
	if err != nil {
		return ApplyReport{}, err
	}
	if err := requirePasswords(steps); err != nil {
		return ApplyReport{}, err
	}
	return a.execute(ctx, steps, res)
}

// requirePasswords refuses, before any request, when a user must be created
// with no password.
//
// §27.6 rule 1: discovering this halfway through an apply leaves the tenant
// part-reconciled, and the fix — supply the password — is one a caller could
// have been told about before anything was written.
func requirePasswords(steps []plannedStep) error {
	var missing []string
	for _, s := range steps {
		if s.step.kind != stepCreateUser {
			continue
		}
		if spec, ok := s.step.spec.(UserSpec); ok && spec.InitialPassword == "" {
			missing = append(missing, spec.Key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &NetworkError{Message: fmt.Sprintf(
		"manifest would create %d user(s) with no InitialPassword: %v. A user cannot be "+
			"created without one, and this is refused before any request rather than part-way "+
			"through an apply (§27.6 rule 1).", len(missing), sortedStrings(missing))}
}

// read gathers the tenant state a plan is computed against.
func (a *ManifestAPI) read(ctx context.Context, m ManagementManifest) (*snapshot, error) {
	start := Limited(planPageSize)
	snap := &snapshot{
		scopes:                 map[uuid.UUID][]Scope{},
		roleGrants:             map[uuid.UUID][]uuid.UUID{},
		roleUserBindings:       map[uuid.UUID][]bindingInfo{},
		roleGroupBindings:      map[uuid.UUID][]bindingInfo{},
		roleServiceAccountBind: map[uuid.UUID][]bindingInfo{},
		groupMembers:           map[uuid.UUID][]uuid.UUID{},
	}

	var err error
	if snap.resources, err = a.c.Resources().ListAll(ctx, start); err != nil {
		return nil, err
	}
	if snap.permissions, err = a.c.Permissions().ListAll(ctx, start); err != nil {
		return nil, err
	}
	if snap.roles, err = a.c.Roles().ListAll(ctx, start); err != nil {
		return nil, err
	}
	if snap.groups, err = a.c.Groups().ListAll(ctx, start); err != nil {
		return nil, err
	}
	if snap.users, err = a.c.Users().ListAll(ctx, start); err != nil {
		return nil, err
	}

	// Only the resources, roles and groups the manifest could match: a tenant
	// with a thousand resources should not cost a thousand scope reads to plan
	// five.
	wantedResources := map[string]bool{}
	for _, r := range m.Resources {
		wantedResources[r.Name] = true
	}
	for _, r := range snap.resources {
		if !wantedResources[r.Name] {
			continue
		}
		scopes, err := a.c.Scopes().List(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		snap.scopes[r.ID] = scopes
	}

	wantedRoles := map[string]bool{}
	for _, r := range m.Roles {
		wantedRoles[r.Name] = true
	}
	for _, r := range snap.roles {
		if !wantedRoles[r.Name] {
			continue
		}
		grants, err := a.c.Roles().ListPermissions(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			snap.roleGrants[r.ID] = append(snap.roleGrants[r.ID], g.Permission.ID)
		}
		users, err := a.c.Roles().ListUsers(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			snap.roleUserBindings[r.ID] = append(snap.roleUserBindings[r.ID], bindingInfo{
				subjectID: u.User.ID, resourceID: u.ResourceID, inherit: u.Inherits(), tenantScope: u.TenantScope,
			})
		}
		groups, err := a.c.Roles().ListGroups(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			snap.roleGroupBindings[r.ID] = append(snap.roleGroupBindings[r.ID], bindingInfo{
				subjectID: g.Group.ID, resourceID: g.ResourceID, inherit: g.Inherits(), tenantScope: g.TenantScope,
			})
		}
		// Only read when the manifest actually has service accounts at
		// all: a manifest without a ServiceAccounts section makes no
		// service-account request (§27.6.1's own framing for the
		// namespace as a whole).
		if len(m.ServiceAccounts) > 0 {
			serviceAccounts, err := a.c.Roles().ListServiceAccounts(ctx, r.ID)
			if err != nil {
				return nil, err
			}
			for _, sa := range serviceAccounts {
				snap.roleServiceAccountBind[r.ID] = append(snap.roleServiceAccountBind[r.ID], bindingInfo{
					subjectID: sa.ServiceAccount.ID, resourceID: sa.ResourceID, inherit: sa.Inherits(), tenantScope: sa.TenantScope,
				})
			}
		}
	}

	if len(m.ServiceAccounts) > 0 {
		if snap.serviceAccounts, err = a.c.ServiceAccounts().ListAll(ctx, start); err != nil {
			return nil, err
		}
	}

	wantedGroups := map[string]bool{}
	for _, g := range m.Groups {
		wantedGroups[g.Name] = true
	}
	for _, g := range snap.groups {
		if !wantedGroups[g.Name] {
			continue
		}
		members, err := a.c.Groups().ListMembersAll(ctx, g.ID, start)
		if err != nil {
			return nil, err
		}
		for _, u := range members {
			snap.groupMembers[g.ID] = append(snap.groupMembers[g.ID], u.ID)
		}
	}
	return snap, nil
}

func containsUUID(haystack []uuid.UUID, needle uuid.UUID) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
