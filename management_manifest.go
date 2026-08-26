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

// GroupSpec is a group and the roles its members inherit.
type GroupSpec struct {
	// Key is the manifest-local identifier users refer to.
	Key string
	// Name is the group's name — its natural key within the tenant.
	Name string
	// Description is human-readable. The server requires one.
	Description string
	// Roles are the Keys of roles assigned to this group.
	Roles []string
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
	// Roles are the Keys of roles assigned directly to this user.
	Roles []string
	// Groups are the Keys of groups this user belongs to.
	Groups []string
}

// ManagementManifest is the shape a tenant should have.
//
// Deliberately covers only the namespaces that describe a tenant's SHAPE.
// Certificates, CA certificates, PGP keys and SCIM tokens are absent on purpose
// (§27.6): they mint one-time secrets, and a declarative layer that "ensures a
// certificate exists" either re-mints one on every run or silently accepts
// drift. Both are worse than an imperative call made once, on purpose, whose
// result the caller stores.
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

// Group declares a group and the roles its members inherit.
func (b *ManifestBuilder) Group(key, name, description string, roleKeys ...string) *ManifestBuilder {
	b.manifest.Groups = append(b.manifest.Groups, GroupSpec{
		Key: key, Name: name, Description: description, Roles: roleKeys,
	})
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

// AssignRole assigns a role directly to the user named by userKey.
func (b *ManifestBuilder) AssignRole(userKey, roleKey string) *ManifestBuilder {
	for i := range b.manifest.Users {
		if b.manifest.Users[i].Key == userKey {
			b.manifest.Users[i].Roles = append(b.manifest.Users[i].Roles, roleKey)
			return b
		}
	}
	b.problems = append(b.problems, fmt.Sprintf(
		"AssignRole names user %q, which no User call has declared yet", userKey))
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
	var permissionKeyList, roleKeyList, groupKeyList, userKeyList []string
	for _, p := range m.Permissions {
		permissionKeys[p.Key] = true
		permissionKeyList = append(permissionKeyList, p.Key)
	}
	for _, r := range m.Roles {
		roleKeys[r.Key] = true
		roleKeyList = append(roleKeyList, r.Key)
	}
	for _, g := range m.Groups {
		groupKeys[g.Key] = true
		groupKeyList = append(groupKeyList, g.Key)
	}
	for _, u := range m.Users {
		userKeyList = append(userKeyList, u.Key)
	}

	problems = append(problems, duplicateKeys("resource", resourceKeyList)...)
	problems = append(problems, duplicateKeys("scope", scopeKeyList)...)
	problems = append(problems, duplicateKeys("permission", permissionKeyList)...)
	problems = append(problems, duplicateKeys("role", roleKeyList)...)
	problems = append(problems, duplicateKeys("group", groupKeyList)...)
	problems = append(problems, duplicateKeys("user", userKeyList)...)

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
	for _, g := range m.Groups {
		for _, r := range g.Roles {
			if !roleKeys[r] {
				problems = append(problems, fmt.Sprintf(
					"group %q is assigned role %q, which no role declares", g.Key, r))
			}
		}
	}
	for _, u := range m.Users {
		for _, r := range u.Roles {
			if !roleKeys[r] {
				problems = append(problems, fmt.Sprintf(
					"user %q is assigned role %q, which no role declares", u.Key, r))
			}
		}
		for _, g := range u.Groups {
			if !groupKeys[g] {
				problems = append(problems, fmt.Sprintf(
					"user %q is in group %q, which no group declares", u.Key, g))
			}
		}
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
