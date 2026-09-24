package axiam

import (
	"fmt"
	"sort"
	"strings"
)

// The desired shape of a tenant — CONTRACT.md §27.6 and §27.7.
//
// A manifest is a VALUE. It is built before the things in it exist, so it
// cannot name them by UUID; every spec carries a manifest-local Key that other
// specs refer to, and Plan resolves those keys against the tenant's current
// state.
//
// Nothing in this file touches the network and nothing here needs a Client —
// which is what makes a manifest something you can load from configuration,
// commit to a repository, and diff.
//
// §27.7 asks each SDK for the declarative form its users would expect. In Go
// that is two things and this file has both: plain struct literals, and the
// fluent builders below for the callers who would otherwise be counting
// closing braces. Both produce the same ManagementManifest and go through the
// same Plan/Apply — a declarative form that talked to the network itself would
// be a second implementation of §27.6, and the two would disagree.

// ScopeSpec is a scope, always beneath the resource that declares it.
type ScopeSpec struct {
	// Key is the manifest-local identifier a role's grants refer to.
	Key string
	// Name is the scope's name — its natural key within its resource.
	Name string
	// Description is human-readable. The server requires one.
	Description string
}

// ResourceSpec is a resource in the hierarchy, and the scopes beneath it.
type ResourceSpec struct {
	// Key is the manifest-local identifier Parent and grants refer to.
	Key string
	// Name is the resource's name — its natural key within the tenant.
	Name string
	// ResourceType is the server's resource_type discriminator.
	ResourceType string
	// Parent is the Key of this resource's parent, empty if it has none.
	Parent string
	// Scopes are the scopes declared under this resource.
	Scopes []ScopeSpec
	// Metadata is the resource's metadata object (§27.6.1 item 1, contract
	// 1.51). nil means UNSTATED — silent, exactly like every other omitted
	// optional field (rule 3): apply leaves whatever the server already has
	// untouched. A non-nil value, including the explicitly empty
	// map[string]any{}, is STATED: it is sent on Create, and on Update when
	// it differs from what the server reports. The server itself treats a
	// stated {} as equal to "none" — creating a resource with no metadata
	// and one created with metadata: map[string]any{} read back identically
	// — so this SDK does too, rather than inventing a distinction the
	// server does not make.
	//
	// Drift is whole-object JSON value equality, never a key-by-key merge
	// (rule 1): Plan cannot tell you removed a key from a merge that only
	// adds keys, and rule 6's idempotence test would not catch it either,
	// since a merge converges to the same result the second time it runs.
	Metadata map[string]any
}

// PermissionSpec is a permission — an action, tenant-wide.
type PermissionSpec struct {
	// Key is the manifest-local identifier a role's grants refer to.
	Key string
	// Action is the action — the permission's natural key within the tenant.
	Action string
	// Description is human-readable. The server requires one.
	Description string
}

// GrantSpec is one permission granted to a role, optionally narrowed to scopes.
type GrantSpec struct {
	// Permission is the Key of the PermissionSpec being granted.
	Permission string
	// Effect is "allow" or "deny". Empty lets the server default, which is allow.
	//
	// A deny grant overrides EVERY allow, at any depth of the resource
	// hierarchy and at equal specificity — AXIAM's RBAC engine is
	// deny-override, not most-specific-wins.
	Effect string
	// Scopes are the Keys of scopes this grant is narrowed to. Empty means the
	// whole resource.
	Scopes []string
}

// RoleSpec is a role and the permissions granted to it.
type RoleSpec struct {
	// Key is the manifest-local identifier users and groups refer to.
	Key string
	// Name is the role's name — its natural key within the tenant.
	Name string
	// Description is human-readable. The server requires one.
	Description string
	// IsGlobal says whether the role applies tenant-wide rather than to a
	// resource subtree.
	IsGlobal bool
	// Grants are the permissions this role grants.
	Grants []GrantSpec
}

// RoleBinding is one `roles[]` entry of a GroupSpec, UserSpec or
// ServiceAccountSpec (§27.6.1 item 2, contract 1.51). It has two shapes:
//
//   - a PLAIN binding — Resource is empty. No resource, and so no
//     inheritance question: this is the shape every SDK had before 1.51,
//     and the Role helper builds it. A plain binding compares equal, for
//     reconciliation purposes, to the server's assignment carrying no
//     resource_id.
//   - a RESOURCE-SCOPED binding — Resource names a ResourceSpec key. Built
//     with ScopedRole (inherits the resource's descendants, today's and
//     every plain assignment's meaning) or NonInheritedRole ("here only",
//     server T22.11's non-inheritable assignment).
//
// NoInherit is meaningful only when Resource is set, and its zero value
// (false) is "inherits" — so a RoleBinding built by taking a Role() binding
// and only setting Resource, without touching NoInherit, behaves exactly
// like ScopedRole. It is never sent on the wire as `inherit: true`,
// explicitly (rule 2: "An SDK MUST NOT send inherit: true explicitly, so
// that an inheritable assignment's body stays byte-for-byte a pre-1.51
// body") — only `false`, and only when NoInherit is set.
type RoleBinding struct {
	// Role is the manifest-local key of the RoleSpec being bound.
	Role string
	// Resource is the manifest-local key of a ResourceSpec this binding is
	// scoped to. Empty is the plain shape.
	Resource string
	// NoInherit stops a resource-scoped binding at Resource rather than
	// reaching its descendants too. Ignored when Resource is empty.
	NoInherit bool
}

// RoleKey builds the PLAIN RoleBinding shape: roleKey, no resource. Named
// RoleKey rather than Role because this package already exports a Role
// type — the server's role object (roles.get's response) — and the two
// must not collide.
func RoleKey(roleKey string) RoleBinding { return RoleBinding{Role: roleKey} }

// ScopedRole builds a resource-scoped, INHERITING RoleBinding: the
// assignment reaches resourceKey and everything below it — today's meaning
// of every assignment, restated at one resource rather than tenant-wide.
func ScopedRole(roleKey, resourceKey string) RoleBinding {
	return RoleBinding{Role: roleKey, Resource: resourceKey}
}

// NonInheritedRole builds a resource-scoped, NON-inheriting RoleBinding:
// the assignment applies at resourceKey only, never its descendants
// (server T22.11b's "here and no further"). §27.6.1 notes an SDK MAY
// refuse this client-side when roleKey names a global role in the same
// manifest (a global role has no resource to stop at) — Build/Plan do.
func NonInheritedRole(roleKey, resourceKey string) RoleBinding {
	return RoleBinding{Role: roleKey, Resource: resourceKey, NoInherit: true}
}

// GroupSpec is a group and the roles its members inherit.
type GroupSpec struct {
	// Key is the manifest-local identifier users refer to.
	Key string
	// Name is the group's name — its natural key within the tenant.
	Name string
	// Description is human-readable. The server requires one.
	Description string
	// Roles are the bindings assigned to this group (§27.6.1 item 2).
	Roles []RoleBinding
}

// UserSpec is a user, their roles and their group memberships.
type UserSpec struct {
	// Key is the manifest-local identifier.
	Key string
	// Username is the user's natural key within the tenant.
	Username string
	// Email is the user's email address.
	Email string
	// InitialPassword is the password to set IF this user has to be created.
	//
	// Never used for a user that already exists: a manifest is a description of
	// shape, and silently resetting a live account's password because a config
	// file mentions one is not a shape change. Plan fails before any request
	// when a user must be created and this is empty, rather than discovering it
	// halfway through an Apply (§27.6 rule 1).
	InitialPassword Sensitive
	// Roles are the bindings assigned directly to this user (§27.6.1
	// item 2).
	Roles []RoleBinding
	// Groups are the Keys of groups this user belongs to.
	Groups []string
}

// ServiceAccountSpec is a service account and the roles bound to it
// (§27.6.1 item 3, contract 1.51).
//
// Reconciled by NAME — the server does not enforce uniqueness on it (only
// client_id is unique), so Plan fails, before any write, when more than
// one existing account matches Name (§27.6.1: "picking one would reconcile
// an arbitrary account").
//
// Status is not a manifest field in 1.51, and there is no Update path for
// Name: only Description is reconciled by Update, matching what the
// contract specifies as the sparse-reconciled field. Group membership of a
// service account is not a manifest field in 1.51 either.
type ServiceAccountSpec struct {
	// Key is the manifest-local identifier role bindings refer to.
	Key string
	// Name is the account's name — reconciled by, but NOT enforced unique
	// by, the server. See the type doc.
	Name string
	// Description is the only field an Update reconciles.
	Description string
	// Roles are the bindings assigned to this service account (§27.6.1
	// item 2), through roles.assign_to_service_account.
	Roles []RoleBinding
}

// ManagementManifest is the shape a tenant should have.
//
// Deliberately covers only the namespaces that describe a tenant's SHAPE.
// Certificates, CA certificates, PGP keys and SCIM tokens are absent on purpose
// (§27.6): they mint one-time secrets, and a declarative layer that "ensures a
// certificate exists" either re-mints one on every run or silently accepts
// drift. Both are worse than an imperative call made once, on purpose, whose
// result the caller stores.
//
// ServiceAccounts is the one exception, and §27.5 rule 5 says why: a
// service account has a stable identity apart from its one-time
// client_secret, so the secret is minted once, at Create, and every later
// Apply of the same manifest is NoChange — never a re-mint. A certificate
// IS its key material, so "ensure it exists" has no answer that is not a
// re-mint, which is why certificates stay out. webhooks is likewise NOT
// covered: the contract names it as an addition this SDK MAY implement,
// and this SDK declines it — no consumer has asked, and its secret is
// caller-supplied rather than minted, so nothing about §27.5 forces the
// choice either way (see README's Contract conformance table).
type ManagementManifest struct {
	// Resources may be in any order — Plan sorts them so a parent precedes its
	// children.
	Resources []ResourceSpec
	// Permissions are tenant-wide actions. What binds one to a resource is the
	// scope list on a role's grant.
	Permissions []PermissionSpec
	// Roles are roles and the permissions granted to them.
	Roles []RoleSpec
	// Groups are groups and the roles their members inherit.
	Groups []GroupSpec
	// Users are users, their role assignments and their group memberships.
	Users []UserSpec
	// ServiceAccounts are service accounts and their role bindings
	// (§27.6.1 item 3, contract 1.51). Read and reconciled only when
	// non-empty: a manifest naming none makes no service-account request
	// at all.
	ServiceAccounts []ServiceAccountSpec
}

// ---------------------------------------------------------------------------
// The builder form (§27.7)
// ---------------------------------------------------------------------------

// ManifestBuilder assembles a ManagementManifest fluently.
//
// The struct-literal form is fine for a small manifest and gets unreadable for
// a real one — nested slices of slices, counting closing braces. This is the
// same value, built a line at a time. Build validates on the way out, exactly
// as a hand-built manifest is validated by Plan, so a dangling key or a cycle
// in the resource parents is caught where the manifest is WRITTEN.
//
//	shape, err := NewManifest().
//	    Resource("docs", "documents", "collection").
//	    Scope("docs", "draft", "draft", "Unpublished").
//	    Permission("read", "document:read", "Read a document").
//	    Role("editor", "Editor", "Edits documents").
//	    Grant("editor", "read", "", "draft").
//	    Build()
type ManifestBuilder struct {
	manifest ManagementManifest
	problems []string
}

// NewManifest starts an empty builder.
func NewManifest() *ManifestBuilder { return &ManifestBuilder{} }

// Resource declares a root resource.
func (b *ManifestBuilder) Resource(key, name, resourceType string) *ManifestBuilder {
	b.manifest.Resources = append(b.manifest.Resources, ResourceSpec{
		Key: key, Name: name, ResourceType: resourceType,
	})
	return b
}

// ChildResource declares a resource beneath the resource named by parentKey.
func (b *ManifestBuilder) ChildResource(key, name, resourceType, parentKey string) *ManifestBuilder {
	b.manifest.Resources = append(b.manifest.Resources, ResourceSpec{
		Key: key, Name: name, ResourceType: resourceType, Parent: parentKey,
	})
	return b
}

// Scope declares a scope beneath the resource named by resourceKey.
func (b *ManifestBuilder) Scope(resourceKey, key, name, description string) *ManifestBuilder {
	for i := range b.manifest.Resources {
		if b.manifest.Resources[i].Key == resourceKey {
			b.manifest.Resources[i].Scopes = append(b.manifest.Resources[i].Scopes, ScopeSpec{
				Key: key, Name: name, Description: description,
			})
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"scope %q names resource %q, which no Resource call has declared yet", key, resourceKey))
	return b
}

// Permission declares a permission.
func (b *ManifestBuilder) Permission(key, action, description string) *ManifestBuilder {
	b.manifest.Permissions = append(b.manifest.Permissions, PermissionSpec{
		Key: key, Action: action, Description: description,
	})
	return b
}

// Role declares a resource-scoped role.
func (b *ManifestBuilder) Role(key, name, description string) *ManifestBuilder {
	b.manifest.Roles = append(b.manifest.Roles, RoleSpec{Key: key, Name: name, Description: description})
	return b
}

// GlobalRole declares a tenant-wide role.
func (b *ManifestBuilder) GlobalRole(key, name, description string) *ManifestBuilder {
	b.manifest.Roles = append(b.manifest.Roles, RoleSpec{
		Key: key, Name: name, Description: description, IsGlobal: true,
	})
	return b
}

// Grant grants a permission to the role named by roleKey.
//
// effect is "allow", "deny", or empty for the server's default. scopeKeys
// narrows the grant; passing none grants it across the whole resource.
func (b *ManifestBuilder) Grant(roleKey, permissionKey, effect string, scopeKeys ...string) *ManifestBuilder {
	for i := range b.manifest.Roles {
		if b.manifest.Roles[i].Key == roleKey {
			b.manifest.Roles[i].Grants = append(b.manifest.Roles[i].Grants, GrantSpec{
				Permission: permissionKey, Effect: effect, Scopes: scopeKeys,
			})
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"grant of %q names role %q, which no Role call has declared yet", permissionKey, roleKey))
	return b
}

// Group declares a group and the PLAIN role bindings its members inherit
// (roleKeys becomes []RoleBinding via Role — no resource scope). Use
// GroupRole afterward for a resource-scoped or non-inheriting binding
// (§27.6.1 item 2).
func (b *ManifestBuilder) Group(key, name, description string, roleKeys ...string) *ManifestBuilder {
	bindings := make([]RoleBinding, len(roleKeys))
	for i, rk := range roleKeys {
		bindings[i] = RoleKey(rk)
	}
	b.manifest.Groups = append(b.manifest.Groups, GroupSpec{
		Key: key, Name: name, Description: description, Roles: bindings,
	})
	return b
}

// GroupRole adds one RoleBinding — plain (Role), resource-scoped
// (ScopedRole) or non-inheriting (NonInheritedRole) — to the group named
// by groupKey (§27.6.1 item 2).
func (b *ManifestBuilder) GroupRole(groupKey string, binding RoleBinding) *ManifestBuilder {
	for i := range b.manifest.Groups {
		if b.manifest.Groups[i].Key == groupKey {
			b.manifest.Groups[i].Roles = append(b.manifest.Groups[i].Roles, binding)
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"GroupRole names group %q, which no Group call has declared yet", groupKey))
	return b
}

// User declares a user. initialPassword is used only if the user has to be
// created; it is never sent for one that already exists.
func (b *ManifestBuilder) User(key, username, email string, initialPassword Sensitive) *ManifestBuilder {
	b.manifest.Users = append(b.manifest.Users, UserSpec{
		Key: key, Username: username, Email: email, InitialPassword: initialPassword,
	})
	return b
}

// AssignRole assigns a PLAIN role binding (RoleKey(roleKey) — no resource
// scope) directly to the user named by userKey. Use UserRole for a
// resource-scoped or non-inheriting binding (§27.6.1 item 2).
func (b *ManifestBuilder) AssignRole(userKey, roleKey string) *ManifestBuilder {
	return b.UserRole(userKey, RoleKey(roleKey))
}

// UserRole adds one RoleBinding — plain (Role), resource-scoped
// (ScopedRole) or non-inheriting (NonInheritedRole) — directly to the user
// named by userKey (§27.6.1 item 2).
func (b *ManifestBuilder) UserRole(userKey string, binding RoleBinding) *ManifestBuilder {
	for i := range b.manifest.Users {
		if b.manifest.Users[i].Key == userKey {
			b.manifest.Users[i].Roles = append(b.manifest.Users[i].Roles, binding)
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"UserRole names user %q, which no User call has declared yet", userKey))
	return b
}

// ServiceAccount declares a service account (§27.6.1 item 3, contract
// 1.51). description may be empty.
func (b *ManifestBuilder) ServiceAccount(key, name, description string) *ManifestBuilder {
	b.manifest.ServiceAccounts = append(b.manifest.ServiceAccounts, ServiceAccountSpec{
		Key: key, Name: name, Description: description,
	})
	return b
}

// ServiceAccountRole adds one RoleBinding to the service account named by
// saKey (§27.6.1 items 2 and 3).
func (b *ManifestBuilder) ServiceAccountRole(saKey string, binding RoleBinding) *ManifestBuilder {
	for i := range b.manifest.ServiceAccounts {
		if b.manifest.ServiceAccounts[i].Key == saKey {
			b.manifest.ServiceAccounts[i].Roles = append(b.manifest.ServiceAccounts[i].Roles, binding)
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"ServiceAccountRole names service account %q, which no ServiceAccount call has declared yet", saKey))
	return b
}

// ResourceMetadata states a metadata object on the resource named by
// resourceKey (§27.6.1 item 1, contract 1.51) — including an explicitly
// empty map[string]any{}, which the server treats as equal to "none". Not
// calling this at all leaves the resource's metadata UNSTATED, which Plan
// treats as "say nothing", not "clear it" (rule 3).
func (b *ManifestBuilder) ResourceMetadata(resourceKey string, metadata map[string]any) *ManifestBuilder {
	for i := range b.manifest.Resources {
		if b.manifest.Resources[i].Key == resourceKey {
			b.manifest.Resources[i].Metadata = metadata
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"ResourceMetadata names resource %q, which no Resource/ChildResource call has declared yet", resourceKey))
	return b
}

// AddToGroup puts the user named by userKey into the group named by groupKey.
func (b *ManifestBuilder) AddToGroup(userKey, groupKey string) *ManifestBuilder {
	for i := range b.manifest.Users {
		if b.manifest.Users[i].Key == userKey {
			b.manifest.Users[i].Groups = append(b.manifest.Users[i].Groups, groupKey)
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"AddToGroup names user %q, which no User call has declared yet", userKey))
	return b
}

// Build returns the assembled manifest, or the reason it cannot be reconciled.
//
// Validated here rather than at Plan time: a dangling key, a duplicate, or a
// cycle in the resource parents is a mistake in the declaration, and hearing
// about it at the declaration is what makes this form worth having.
func (b *ManifestBuilder) Build() (ManagementManifest, error) {
	if len(b.problems) > 0 {
		return ManagementManifest{}, &NetworkError{Message: fmt.Sprintf(
			"manifest builder found %d problem(s): %s", len(b.problems), strings.Join(b.problems, "; "))}
	}
	if err := validateManifest(b.manifest); err != nil {
		return ManagementManifest{}, err
	}
	return b.manifest, nil
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// validateManifest rejects a manifest that cannot be reconciled, before any
// request is made.
//
// §27.6 rules 2 and 5 both land here. Every failure this catches would
// otherwise surface halfway through an Apply, with part of the tenant already
// changed — which is the expensive moment to learn that a role refers to a
// permission nobody declared. Every problem is reported, not just the first:
// fixing them one at a time is a slow way to learn about four.
func validateManifest(m ManagementManifest) error {
	var problems []string

	resourceKeys := map[string]bool{}
	scopeKeys := map[string]bool{}
	permissionKeys := map[string]bool{}
	roleKeys := map[string]bool{}
	groupKeys := map[string]bool{}

	var resourceKeyList, scopeKeyList []string
	for _, r := range m.Resources {
		resourceKeys[r.Key] = true
		resourceKeyList = append(resourceKeyList, r.Key)
		for _, s := range r.Scopes {
			scopeKeys[s.Key] = true
			scopeKeyList = append(scopeKeyList, s.Key)
		}
	}
	globalRoles := map[string]bool{}
	var permissionKeyList, roleKeyList, groupKeyList, userKeyList, serviceAccountKeyList []string
	for _, p := range m.Permissions {
		permissionKeys[p.Key] = true
		permissionKeyList = append(permissionKeyList, p.Key)
	}
	for _, r := range m.Roles {
		roleKeys[r.Key] = true
		roleKeyList = append(roleKeyList, r.Key)
		if r.IsGlobal {
			globalRoles[r.Key] = true
		}
	}
	for _, g := range m.Groups {
		groupKeys[g.Key] = true
		groupKeyList = append(groupKeyList, g.Key)
	}
	for _, u := range m.Users {
		userKeyList = append(userKeyList, u.Key)
	}
	for _, sa := range m.ServiceAccounts {
		serviceAccountKeyList = append(serviceAccountKeyList, sa.Key)
	}

	problems = append(problems, duplicateKeys("resource", resourceKeyList)...)
	problems = append(problems, duplicateKeys("scope", scopeKeyList)...)
	problems = append(problems, duplicateKeys("permission", permissionKeyList)...)
	problems = append(problems, duplicateKeys("role", roleKeyList)...)
	problems = append(problems, duplicateKeys("group", groupKeyList)...)
	problems = append(problems, duplicateKeys("user", userKeyList)...)
	problems = append(problems, duplicateKeys("service account", serviceAccountKeyList)...)

	for _, r := range m.Resources {
		if r.Parent != "" && !resourceKeys[r.Parent] {
			problems = append(problems, fmt.Sprintf(
				"resource %q names parent %q, which no resource declares", r.Key, r.Parent))
		}
	}
	for _, r := range m.Roles {
		for _, g := range r.Grants {
			if !permissionKeys[g.Permission] {
				problems = append(problems, fmt.Sprintf(
					"role %q grants permission %q, which no permission declares", r.Key, g.Permission))
			}
			for _, s := range g.Scopes {
				if !scopeKeys[s] {
					problems = append(problems, fmt.Sprintf(
						"role %q scopes a grant to %q, which no scope declares", r.Key, s))
				}
			}
		}
	}

	// validateRoleBindings covers §27.6.1 item 2 for one subject (a group,
	// user or service account): every binding names a role and, when
	// scoped, a resource that the manifest actually declares; a binding to
	// a GLOBAL role with NoInherit is refused client-side (§27.6.1: "An SDK
	// MAY check it client-side when the role is in the manifest" — a
	// global role has no resource to stop at, so this SDK does); and no
	// role is bound twice to the same subject, plain-and-scoped included
	// (§27.6.1: "A subject holds a role at most once ... An SDK MUST
	// reject it before any request, naming the subject and the role" —
	// the server's has_role key is (subject, role) with no resource
	// component, so two bindings of the same role describe a state the
	// server cannot hold, whatever resource each one names).
	validateRoleBindings := func(kind, subjectKey string, bindings []RoleBinding) {
		seenRole := map[string]bool{}
		for _, rb := range bindings {
			if !roleKeys[rb.Role] {
				problems = append(problems, fmt.Sprintf(
					"%s %q is assigned role %q, which no role declares", kind, subjectKey, rb.Role))
			}
			if rb.Resource != "" && !resourceKeys[rb.Resource] {
				problems = append(problems, fmt.Sprintf(
					"%s %q binds role %q to resource %q, which no resource declares", kind, subjectKey, rb.Role, rb.Resource))
			}
			if rb.NoInherit && rb.Resource != "" && globalRoles[rb.Role] {
				problems = append(problems, fmt.Sprintf(
					"%s %q binds global role %q with NoInherit, which the server refuses (a global role has no resource to stop at)", kind, subjectKey, rb.Role))
			}
			if seenRole[rb.Role] {
				problems = append(problems, fmt.Sprintf(
					"%s %q is assigned role %q more than once (§27.6.1: a subject holds a role at most once, plain and resource-scoped bindings included)", kind, subjectKey, rb.Role))
			}
			seenRole[rb.Role] = true
		}
	}

	for _, g := range m.Groups {
		validateRoleBindings("group", g.Key, g.Roles)
	}
	for _, u := range m.Users {
		validateRoleBindings("user", u.Key, u.Roles)
		for _, g := range u.Groups {
			if !groupKeys[g] {
				problems = append(problems, fmt.Sprintf(
					"user %q is in group %q, which no group declares", u.Key, g))
			}
		}
	}
	for _, sa := range m.ServiceAccounts {
		validateRoleBindings("service account", sa.Key, sa.Roles)
	}

	if _, err := topologicalOrder(m); err != nil {
		var ne *NetworkError
		if ok := asNetworkError(err, &ne); ok {
			problems = append(problems, ne.Message)
		} else {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return &NetworkError{Message: fmt.Sprintf(
			"manifest is not reconcilable (%d problem(s)): %s", len(problems), strings.Join(problems, "; "))}
	}
	return nil
}

func asNetworkError(err error, target **NetworkError) bool {
	if ne, ok := err.(*NetworkError); ok {
		*target = ne
		return true
	}
	return false
}

func duplicateKeys(kind string, keys []string) []string {
	seen := map[string]bool{}
	var problems []string
	for _, k := range keys {
		if seen[k] {
			problems = append(problems, fmt.Sprintf("%s key %q is declared more than once", kind, k))
		}
		seen[k] = true
	}
	return problems
}

// topologicalOrder returns resource keys ordered so a parent always precedes
// its children.
//
// Returns an error on a cycle rather than looping: a resource graph with a
// cycle has no valid creation order, and discovering that by hanging is worse
// than discovering it by message.
func topologicalOrder(m ManagementManifest) ([]string, error) {
	parents := map[string]string{}
	for _, r := range m.Resources {
		parents[r.Key] = r.Parent
	}
	var order []string
	placed := map[string]bool{}

	// Iterate the manifest's own order so the result is stable run to run
	// (§27.6 rule 8), rather than a map traversal order that is not.
	for _, r := range m.Resources {
		var chain []string
		guard := map[string]bool{}
		cursor := r.Key
		for cursor != "" && !placed[cursor] {
			if guard[cursor] {
				return nil, &NetworkError{Message: fmt.Sprintf(
					"resource parent graph has a cycle through %q; there is no order in which "+
						"these can be created", cursor)}
			}
			guard[cursor] = true
			chain = append(chain, cursor)
			cursor = parents[cursor]
		}
		for i := len(chain) - 1; i >= 0; i-- {
			if !placed[chain[i]] {
				placed[chain[i]] = true
				order = append(order, chain[i])
			}
		}
	}
	return order, nil
}

// sortedStrings returns a sorted copy, for stable messages.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
