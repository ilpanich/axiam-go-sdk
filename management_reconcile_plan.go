package axiam

import (
	"fmt"

	"github.com/google/uuid"
)

// computeSteps is the ordered work that would reconcile a manifest.
//
// Pure: it reads the snapshot, fills res with the ids of things that already
// exist, and returns the work. Nothing here touches the network, which is what
// lets Plan promise it writes nothing.
func computeSteps(m ManagementManifest, snap *snapshot, res *resolved) []plannedStep {
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
			if existing.ResourceType != spec.ResourceType {
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
		for _, roleKey := range group.Roles {
			summary := fmt.Sprintf("role %q on group %q", roleKey, group.Name)
			roleID, roleKnown := res.roles[roleKey]
			groupID, groupKnown := res.groups[group.Key]
			if roleKnown && groupKnown && containsUUID(snap.roleGroups[roleID], groupID) {
				push(ChangeNone, TargetGroupRole, group.Key, summary, step{kind: stepNoop, key: group.Key})
				continue
			}
			push(ChangeCreate, TargetGroupRole, group.Key, summary,
				step{kind: stepAssignRoleToGroup, key: group.Key, spec: roleKey, related: group.Key})
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
		for _, roleKey := range user.Roles {
			summary := fmt.Sprintf("role %q on user %q", roleKey, user.Username)
			roleID, roleKnown := res.roles[roleKey]
			userID, userKnown := res.users[user.Key]
			if roleKnown && userKnown && containsUUID(snap.roleUsers[roleID], userID) {
				push(ChangeNone, TargetUserRole, user.Key, summary, step{kind: stepNoop, key: user.Key})
				continue
			}
			push(ChangeCreate, TargetUserRole, user.Key, summary,
				step{kind: stepAssignRoleToUser, key: user.Key, spec: roleKey, related: user.Key})
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

	return out
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
