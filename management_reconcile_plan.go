package axiam

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// metadataStateEqual is §27.6.1 item 1's drift rule: whole-object JSON
// value equality, never a key-by-key merge. nil (on either side) is
// normalized to an empty object first, because that IS what "no metadata"
// means on the wire — a stated map[string]any{} is defined to equal what
// the server stores for a resource created with none, and a nil Resource
// .Metadata (a server that predates the field, or a decode edge case)
// reads the same way rather than as a comparison this SDK cannot make.
func metadataStateEqual(spec map[string]any, current any) bool {
	if spec == nil {
		spec = map[string]any{}
	}
	if current == nil {
		current = map[string]any{}
	}
	specJSON, err1 := json.Marshal(spec)
	currentJSON, err2 := json.Marshal(current)
	if err1 != nil || err2 != nil {
		// Cannot compare: treat as drifted, so Apply attempts the Update
		// rather than silently accepting an unknown state as matching.
		return false
	}
	return string(specJSON) == string(currentJSON)
}

// planRoleBinding is planRoleBindings' single-binding worker: shared by
// groups, users and service accounts, since §27.6.1 item 2's
// Create/Update(rebind)/NoChange logic is identical for all three and
// differs only in which imperative call run() ends up making — decided by
// kind, not by anything here.
func planRoleBinding(
	push func(Change, Target, string, string, step),
	target Target, kind stepKind,
	subjectKey, subjectLabel string,
	binding RoleBinding,
	roleID uuid.UUID, roleKnown bool,
	subjectID uuid.UUID, subjectKnown bool,
	serverBindings []bindingInfo,
	res *resolved,
) {
	summary := fmt.Sprintf("role %q on %s", binding.Role, subjectLabel)
	if binding.Resource != "" {
		scopeWord := "inheriting"
		if binding.NoInherit {
			scopeWord = "non-inheriting"
		}
		summary = fmt.Sprintf("%s at resource %q (%s)", summary, binding.Resource, scopeWord)
	}
	bc := bindingChange{roleKey: binding.Role, subjectKey: subjectKey, binding: binding}

	if !roleKnown || !subjectKnown {
		push(ChangeCreate, target, subjectKey, summary, step{kind: kind, key: subjectKey, spec: bc})
		return
	}
	var current *bindingInfo
	for i := range serverBindings {
		if serverBindings[i].subjectID == subjectID {
			c := serverBindings[i]
			current = &c
			break
		}
	}
	if current == nil {
		push(ChangeCreate, target, subjectKey, summary, step{kind: kind, key: subjectKey, spec: bc})
		return
	}
	resourceOf := func(key string) (uuid.UUID, bool) { id, ok := res.resources[key]; return id, ok }
	if current.sameBinding(binding, resourceOf) {
		push(ChangeNone, target, subjectKey, summary, step{kind: stepNoop, key: subjectKey})
		return
	}
	bc.previous = current
	push(ChangeUpdate, target, subjectKey, summary, step{kind: kind, key: subjectKey, spec: bc})
}

// computeSteps is the ordered work that would reconcile a manifest.
//
// Pure: it reads the snapshot, fills res with the ids of things that already
// exist, and returns the work. Nothing here touches the network, which is what
// lets Plan promise it writes nothing.
func computeSteps(m ManagementManifest, snap *snapshot, res *resolved) ([]plannedStep, error) {
	var out []plannedStep
	push := func(change Change, target Target, key, summary string, s step) {
		out = append(out, plannedStep{
			action: PlannedAction{Change: change, Target: target, Key: key, Summary: summary},
			step:   s,
		})
	}

	specs := map[string]ResourceSpec{}
	for _, r := range m.Resources {
		specs[r.Key] = r
	}
	// validateManifest already rejected a cycle, so this cannot error here.
	order, _ := topologicalOrder(m)
	for _, key := range order {
		spec := specs[key]
		parentPending := spec.Parent != "" && !hasKey(res.resources, spec.Parent)
		var parentID *uuid.UUID
		if spec.Parent != "" {
			if id, ok := res.resources[spec.Parent]; ok {
				parentID = &id
			}
		}
		// A child whose parent is itself pending cannot already exist, so
		// matching it against a root of the same name would be wrong.
		var existing *Resource
		if !parentPending {
			for i := range snap.resources {
				r := snap.resources[i]
				if r.Name != spec.Name {
					continue
				}
				if samePointerUUID(r.ParentID, parentID) {
					existing = &snap.resources[i]
					break
				}
			}
		}
		summary := fmt.Sprintf("resource %q (%s)", spec.Name, spec.ResourceType)
		if existing != nil {
			res.resources[key] = existing.ID
			metadataDrifted := spec.Metadata != nil && !metadataStateEqual(spec.Metadata, existing.Metadata)
			if existing.ResourceType != spec.ResourceType || metadataDrifted {
				push(ChangeUpdate, TargetResource, key, summary, step{kind: stepUpdateResource, key: key, spec: spec})
			} else {
				push(ChangeNone, TargetResource, key, summary, step{kind: stepNoop, key: key})
			}
			continue
		}
		push(ChangeCreate, TargetResource, key, summary, step{kind: stepCreateResource, key: key, spec: spec})
	}

	for _, spec := range m.Resources {
		var current []Scope
		if id, ok := res.resources[spec.Key]; ok {
			current = snap.scopes[id]
		}
		for _, sc := range spec.Scopes {
			summary := fmt.Sprintf("scope %q under resource %q", sc.Name, spec.Name)
			found := false
			for _, existing := range current {
				if existing.Name == sc.Name {
					res.scopes[sc.Key] = existing.ID
					found = true
					break
				}
			}
			if found {
				push(ChangeNone, TargetScope, sc.Key, summary, step{kind: stepNoop, key: sc.Key})
				continue
			}
			push(ChangeCreate, TargetScope, sc.Key, summary,
				step{kind: stepCreateScope, key: sc.Key, spec: sc, related: spec.Key})
		}
	}

	for _, spec := range m.Permissions {
		summary := fmt.Sprintf("permission %q", spec.Action)
		var found *Permission
		for i := range snap.permissions {
			if snap.permissions[i].Action == spec.Action {
				found = &snap.permissions[i]
				break
			}
		}
		if found != nil {
			res.permissions[spec.Key] = found.ID
			if found.Description != spec.Description {
				push(ChangeUpdate, TargetPermission, spec.Key, summary,
					step{kind: stepUpdatePermission, key: spec.Key, spec: spec})
			} else {
				push(ChangeNone, TargetPermission, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
			}
			continue
		}
		push(ChangeCreate, TargetPermission, spec.Key, summary,
			step{kind: stepCreatePermission, key: spec.Key, spec: spec})
	}

	for _, spec := range m.Roles {
		summary := fmt.Sprintf("role %q", spec.Name)
		var found *Role
		for i := range snap.roles {
			if snap.roles[i].Name == spec.Name {
				found = &snap.roles[i]
				break
			}
		}
		if found != nil {
			res.roles[spec.Key] = found.ID
			if found.Description != spec.Description || found.IsGlobal != spec.IsGlobal {
				push(ChangeUpdate, TargetRole, spec.Key, summary, step{kind: stepUpdateRole, key: spec.Key, spec: spec})
			} else {
				push(ChangeNone, TargetRole, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
			}
			continue
		}
		push(ChangeCreate, TargetRole, spec.Key, summary, step{kind: stepCreateRole, key: spec.Key, spec: spec})
	}

	for _, role := range m.Roles {
		var granted []uuid.UUID
		if id, ok := res.roles[role.Key]; ok {
			granted = snap.roleGrants[id]
		}
		for _, grant := range role.Grants {
			summary := fmt.Sprintf("grant %q to role %q", grant.Permission, role.Name)
			permissionID, known := res.permissions[grant.Permission]
			if known && containsUUID(granted, permissionID) {
				push(ChangeNone, TargetRoleGrant, role.Key, summary, step{kind: stepNoop, key: role.Key})
				continue
			}
			push(ChangeCreate, TargetRoleGrant, role.Key, summary,
				step{kind: stepGrantPermission, key: role.Key, spec: grant, related: role.Key})
		}
	}

	for _, spec := range m.Groups {
		summary := fmt.Sprintf("group %q", spec.Name)
		var found *Group
		for i := range snap.groups {
			if snap.groups[i].Name == spec.Name {
				found = &snap.groups[i]
				break
			}
		}
		if found != nil {
			res.groups[spec.Key] = found.ID
			if found.Description != spec.Description {
				push(ChangeUpdate, TargetGroup, spec.Key, summary, step{kind: stepUpdateGroup, key: spec.Key, spec: spec})
			} else {
				push(ChangeNone, TargetGroup, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
			}
			continue
		}
		push(ChangeCreate, TargetGroup, spec.Key, summary, step{kind: stepCreateGroup, key: spec.Key, spec: spec})
	}

	for _, group := range m.Groups {
		for _, binding := range group.Roles {
			roleID, roleKnown := res.roles[binding.Role]
			groupID, groupKnown := res.groups[group.Key]
			planRoleBinding(push, TargetGroupRole, stepBindRoleToGroup,
				group.Key, fmt.Sprintf("group %q", group.Name), binding,
				roleID, roleKnown, groupID, groupKnown, snap.roleGroupBindings[roleID], res)
		}
	}

	for _, spec := range m.Users {
		summary := fmt.Sprintf("user %q", spec.Username)
		var found *UserResponse
		for i := range snap.users {
			if snap.users[i].Username == spec.Username {
				found = &snap.users[i]
				break
			}
		}
		if found != nil {
			res.users[spec.Key] = found.ID
			if found.Email != spec.Email {
				push(ChangeUpdate, TargetUser, spec.Key, summary, step{kind: stepUpdateUser, key: spec.Key, spec: spec})
			} else {
				push(ChangeNone, TargetUser, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
			}
			continue
		}
		push(ChangeCreate, TargetUser, spec.Key, summary, step{kind: stepCreateUser, key: spec.Key, spec: spec})
	}

	for _, user := range m.Users {
		for _, binding := range user.Roles {
			roleID, roleKnown := res.roles[binding.Role]
			userID, userKnown := res.users[user.Key]
			planRoleBinding(push, TargetUserRole, stepBindRoleToUser,
				user.Key, fmt.Sprintf("user %q", user.Username), binding,
				roleID, roleKnown, userID, userKnown, snap.roleUserBindings[roleID], res)
		}
	}

	for _, user := range m.Users {
		for _, groupKey := range user.Groups {
			summary := fmt.Sprintf("user %q in group %q", user.Username, groupKey)
			groupID, groupKnown := res.groups[groupKey]
			userID, userKnown := res.users[user.Key]
			if groupKnown && userKnown && containsUUID(snap.groupMembers[groupID], userID) {
				push(ChangeNone, TargetGroupMember, user.Key, summary, step{kind: stepNoop, key: user.Key})
				continue
			}
			push(ChangeCreate, TargetGroupMember, user.Key, summary,
				step{kind: stepAddGroupMember, key: user.Key, spec: groupKey, related: user.Key})
		}
	}

	// Service accounts and their role bindings — ORDERED LAST (§27.6 rule
	// 5, amended by §27.6.1 for contract 1.51), and read/planned only when
	// the manifest names any (a.read already skipped the requests
	// otherwise, so snap.serviceAccounts and every roleServiceAccountBind
	// entry are simply empty here).
	for _, spec := range m.ServiceAccounts {
		summary := fmt.Sprintf("service account %q", spec.Name)
		var matches []ServiceAccountResponse
		for i := range snap.serviceAccounts {
			if snap.serviceAccounts[i].Name == spec.Name {
				matches = append(matches, snap.serviceAccounts[i])
			}
		}
		if len(matches) > 1 {
			// §27.6.1 item 3: "plan MUST fail with a client-side error,
			// before apply writes anything, when more than one existing
			// account matches a stated name. Picking one would reconcile
			// an arbitrary account."
			return nil, &NetworkError{Message: fmt.Sprintf(
				"service account %q (manifest key %q) matches %d existing accounts by name; "+
					"the server does not enforce name uniqueness, and picking one would reconcile "+
					"an arbitrary account — rename in the manifest or delete the duplicate(s) first",
				spec.Name, spec.Key, len(matches))}
		}
		if len(matches) == 1 {
			found := matches[0]
			res.serviceAccounts[spec.Key] = found.ID
			wantDescription := ""
			if spec.Description != "" {
				wantDescription = spec.Description
			}
			currentDescription := ""
			if found.Description != nil {
				currentDescription = *found.Description
			}
			if wantDescription != currentDescription {
				push(ChangeUpdate, TargetServiceAccount, spec.Key, summary,
					step{kind: stepUpdateServiceAccount, key: spec.Key, spec: spec})
			} else {
				push(ChangeNone, TargetServiceAccount, spec.Key, summary, step{kind: stepNoop, key: spec.Key})
			}
			continue
		}
		push(ChangeCreate, TargetServiceAccount, spec.Key, summary,
			step{kind: stepCreateServiceAccount, key: spec.Key, spec: spec})
	}

	for _, sa := range m.ServiceAccounts {
		for _, binding := range sa.Roles {
			roleID, roleKnown := res.roles[binding.Role]
			saID, saKnown := res.serviceAccounts[sa.Key]
			planRoleBinding(push, TargetServiceAccountRole, stepBindRoleToServiceAccount,
				sa.Key, fmt.Sprintf("service account %q", sa.Name), binding,
				roleID, roleKnown, saID, saKnown, snap.roleServiceAccountBind[roleID], res)
		}
	}

	return out, nil
}

func hasKey(m map[string]uuid.UUID, key string) bool {
	_, ok := m[key]
	return ok
}

func samePointerUUID(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
