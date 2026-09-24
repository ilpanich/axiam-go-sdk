package axiam

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// execute runs every step in order, stopping at the first failure (§27.6 rule 7).
func (a *ManifestAPI) execute(ctx context.Context, steps []plannedStep, res *resolved) (ApplyReport, error) {
	report := ApplyReport{}
	stopped := false
	for _, planned := range steps {
		if stopped {
			report.Steps = append(report.Steps, AppliedStep{
				Action: planned.action, Outcome: StepOutcome{Status: StatusNotAttempted},
			})
			continue
		}
		if planned.step.kind == stepNoop {
			report.Steps = append(report.Steps, AppliedStep{
				Action: planned.action, Outcome: StepOutcome{Status: StatusUnchanged},
			})
			continue
		}
		created, err := a.run(ctx, planned.step, res)
		if err != nil {
			if rf, ok := err.(*rebindFailure); ok {
				// §27.6.1: "If the assign fails, the SDK MUST attempt to
				// assign the previous binding again ... and report both
				// outcomes" — the failed rebind AND the restore attempt,
				// as two AppliedSteps.
				report.Steps = append(report.Steps, AppliedStep{
					Action:  planned.action,
					Outcome: StepOutcome{Status: StatusFailed, Message: rf.assignErr.Error()},
				})
				restoreStatus, restoreMessage := StatusRestored, ""
				if rf.restoreErr != nil {
					restoreStatus, restoreMessage = StatusRestoreFailed, rf.restoreErr.Error()
				}
				report.Steps = append(report.Steps, AppliedStep{
					Action: PlannedAction{
						Change:  ChangeUpdate,
						Target:  planned.action.Target,
						Key:     planned.action.Key,
						Summary: "restore the previous binding after a failed rebind: " + planned.action.Summary,
					},
					Outcome: StepOutcome{Status: restoreStatus, Message: restoreMessage},
				})
				stopped = true
				continue
			}
			report.Steps = append(report.Steps, AppliedStep{
				Action:  planned.action,
				Outcome: StepOutcome{Status: StatusFailed, Message: err.Error()},
			})
			stopped = true
			continue
		}
		// The step's own Change already says create vs. update — more
		// robust than guessing from the step-kind string, which a
		// two-shape role binding's single kind (stepBindRoleTo*) does not
		// encode: the very same kind is a Create step for a brand-new
		// binding and an Update (rebind) step for one that already
		// existed with a different resource/inherit.
		status := StatusCreated
		if planned.action.Change == ChangeUpdate {
			status = StatusUpdated
		}
		outcome := StepOutcome{Status: status}
		if created != nil {
			outcome.CreatedServiceAccount = created
		}
		report.Steps = append(report.Steps, AppliedStep{
			Action: planned.action, Outcome: outcome,
		})
	}
	return report, nil
}

// run carries out one step, recording any id it mints.
// run carries out one step, recording any id it mints. The
// *ServiceAccountCreatedResponse return is non-nil ONLY for a successful
// stepCreateServiceAccount (§27.5 rule 5) — execute() attaches it to that
// step's StepOutcome.
func (a *ManifestAPI) run(ctx context.Context, s step, res *resolved) (*ServiceAccountCreatedResponse, error) {
	c := a.c
	switch s.kind {
	case stepCreateResource:
		spec := s.spec.(ResourceSpec)
		body := CreateResourceRequest{Name: spec.Name, ResourceType: spec.ResourceType}
		if spec.Parent != "" {
			if parent, ok := res.resources[spec.Parent]; ok {
				body.ParentID = &parent
			}
		}
		if spec.Metadata != nil {
			var v any = spec.Metadata
			body.Metadata = &v
		}
		created, err := c.Resources().Create(ctx, body)
		if err != nil {
			return nil, err
		}
		res.resources[s.key] = created.ID
		return nil, nil

	case stepUpdateResource:
		spec := s.spec.(ResourceSpec)
		body := UpdateResourceRequest{ResourceType: ptr(spec.ResourceType)}
		if spec.Metadata != nil {
			var v any = spec.Metadata
			body.Metadata = &v
		}
		_, err := c.Resources().Update(ctx, res.resources[s.key], body)
		return nil, err

	case stepCreateScope:
		spec := s.spec.(ScopeSpec)
		created, err := c.Scopes().Create(ctx, res.resources[s.related],
			CreateScopeRequest{Name: spec.Name, Description: spec.Description})
		if err != nil {
			return nil, err
		}
		res.scopes[s.key] = created.ID
		return nil, nil

	case stepCreatePermission:
		spec := s.spec.(PermissionSpec)
		created, err := c.Permissions().Create(ctx,
			CreatePermissionRequest{Action: spec.Action, Description: spec.Description})
		if err != nil {
			return nil, err
		}
		res.permissions[s.key] = created.ID
		return nil, nil

	case stepUpdatePermission:
		spec := s.spec.(PermissionSpec)
		_, err := c.Permissions().Update(ctx, res.permissions[s.key],
			UpdatePermissionRequest{Description: ptr(spec.Description)})
		return nil, err

	case stepCreateRole:
		spec := s.spec.(RoleSpec)
		created, err := c.Roles().Create(ctx, CreateRoleRequest{
			Name: spec.Name, Description: spec.Description, IsGlobal: spec.IsGlobal,
		})
		if err != nil {
			return nil, err
		}
		res.roles[s.key] = created.ID
		return nil, nil

	case stepUpdateRole:
		spec := s.spec.(RoleSpec)
		_, err := c.Roles().Update(ctx, res.roles[s.key], UpdateRole{
			Description: ptr(spec.Description), IsGlobal: ptr(spec.IsGlobal),
		})
		return nil, err

	case stepGrantPermission:
		grant := s.spec.(GrantSpec)
		body := GrantPermissionRequest{PermissionID: res.permissions[grant.Permission]}
		if grant.Effect != "" {
			effect := PermissionEffect(grant.Effect)
			body.Effect = &effect
		}
		for _, scopeKey := range grant.Scopes {
			body.ScopeIDs = append(body.ScopeIDs, res.scopes[scopeKey])
		}
		return nil, c.Roles().GrantPermission(ctx, res.roles[s.related], body)

	case stepCreateGroup:
		spec := s.spec.(GroupSpec)
		created, err := c.Groups().Create(ctx,
			CreateGroupRequest{Name: spec.Name, Description: spec.Description})
		if err != nil {
			return nil, err
		}
		res.groups[s.key] = created.ID
		return nil, nil

	case stepUpdateGroup:
		spec := s.spec.(GroupSpec)
		_, err := c.Groups().Update(ctx, res.groups[s.key],
			UpdateGroup{Description: ptr(spec.Description)})
		return nil, err

	case stepBindRoleToGroup:
		bc := s.spec.(bindingChange)
		return nil, a.runGroupBinding(ctx, bc, res)

	case stepCreateUser:
		spec := s.spec.(UserSpec)
		created, err := c.Users().Create(ctx, CreateUserRequest{
			Username: spec.Username, Email: spec.Email, Password: spec.InitialPassword,
		})
		if err != nil {
			return nil, err
		}
		res.users[s.key] = created.ID
		return nil, nil

	case stepUpdateUser:
		spec := s.spec.(UserSpec)
		_, err := c.Users().Update(ctx, res.users[s.key],
			UpdateUserRequest{Email: ptr(spec.Email)})
		return nil, err

	case stepBindRoleToUser:
		bc := s.spec.(bindingChange)
		return nil, a.runUserBinding(ctx, bc, res)

	case stepAddGroupMember:
		groupKey := s.spec.(string)
		return nil, c.Groups().AddMember(ctx, res.groups[groupKey],
			AddMemberRequest{UserID: res.users[s.related]})

	case stepCreateServiceAccount:
		spec := s.spec.(ServiceAccountSpec)
		body := CreateServiceAccountRequest{Name: spec.Name}
		if spec.Description != "" {
			body.Description = ptr(spec.Description)
		}
		created, err := c.ServiceAccounts().Create(ctx, body)
		if err != nil {
			return nil, err
		}
		res.serviceAccounts[s.key] = created.ID
		return &created, nil

	case stepUpdateServiceAccount:
		spec := s.spec.(ServiceAccountSpec)
		_, err := c.ServiceAccounts().Update(ctx, res.serviceAccounts[s.key],
			UpdateServiceAccount{Description: ptr(spec.Description)})
		return nil, err

	case stepBindRoleToServiceAccount:
		bc := s.spec.(bindingChange)
		return nil, a.runServiceAccountBinding(ctx, bc, res)
	}
	// Unreachable: computeSteps emits only the kinds above.
	return nil, &NetworkError{Message: fmt.Sprintf("unknown manifest step %q", s.kind)}
}

// bindingRequest is the three imperative APIs' assign_to_* request shapes,
// reduced to what runXBinding shares: the field is filled in by the
// caller-specific closure the three runXBinding methods each build once.
type bindingRequest struct {
	resourceID  *uuid.UUID
	inherit     *bool
	tenantScope []uuid.UUID
}

// bindingRequestFor builds the shared shape of an assign_to_* body from a
// bindingChange's target binding (resource/inherit) plus, on a rebind, the
// server's own tenant_scope carried across unchanged (§27.6.1: "An
// Update's re-assignment MUST carry the server binding's existing
// tenant_scope across unchanged. Dropping it would silently widen an
// organization-level account's reach").
func bindingRequestFor(bc bindingChange, res *resolved) bindingRequest {
	var req bindingRequest
	if bc.binding.Resource != "" {
		id := res.resources[bc.binding.Resource]
		req.resourceID = &id
		if bc.binding.NoInherit {
			req.inherit = ptr(false)
		}
	}
	if bc.previous != nil {
		req.tenantScope = bc.previous.tenantScope
	}
	return req
}

// restoreRequestFor builds the assign_to_* body that puts bc.previous's
// EXACT shape back — same resource, same inherit, same tenant_scope — used
// only when a rebind's new assign has just failed.
func restoreRequestFor(bc bindingChange) bindingRequest {
	var req bindingRequest
	if bc.previous.resourceID != nil {
		id := *bc.previous.resourceID
		req.resourceID = &id
	}
	if !bc.previous.inherit {
		req.inherit = ptr(false)
	}
	req.tenantScope = bc.previous.tenantScope
	return req
}

// runUserBinding performs a stepBindRoleToUser step — a plain assign for a
// Create (bc.previous == nil), or an unassign-then-assign rebind for an
// Update, restoring the previous binding on a failed re-assign (§27.6.1).
func (a *ManifestAPI) runUserBinding(ctx context.Context, bc bindingChange, res *resolved) error {
	c := a.c
	roleID, userID := res.roles[bc.roleKey], res.users[bc.subjectKey]

	if bc.previous != nil {
		resourceParam := ""
		if bc.previous.resourceID != nil {
			resourceParam = bc.previous.resourceID.String()
		}
		if err := c.Roles().UnassignFromUser(ctx, roleID, userID, resourceParam); err != nil {
			return err // nothing changed yet: an ordinary failure, not a rebindFailure.
		}
	}

	req := bindingRequestFor(bc, res)
	assignErr := c.Roles().AssignToUser(ctx, roleID, AssignRoleToUserRequest{
		UserID: userID, ResourceID: req.resourceID, Inherit: req.inherit, TenantScope: req.tenantScope,
	})
	if assignErr == nil {
		return nil
	}
	if bc.previous == nil {
		return assignErr // a plain Create failed: nothing to restore.
	}
	restore := restoreRequestFor(bc)
	restoreErr := c.Roles().AssignToUser(ctx, roleID, AssignRoleToUserRequest{
		UserID: userID, ResourceID: restore.resourceID, Inherit: restore.inherit, TenantScope: restore.tenantScope,
	})
	return &rebindFailure{assignErr: assignErr, restoreErr: restoreErr}
}

// runGroupBinding mirrors runUserBinding for a group subject.
func (a *ManifestAPI) runGroupBinding(ctx context.Context, bc bindingChange, res *resolved) error {
	c := a.c
	roleID, groupID := res.roles[bc.roleKey], res.groups[bc.subjectKey]

	if bc.previous != nil {
		resourceParam := ""
		if bc.previous.resourceID != nil {
			resourceParam = bc.previous.resourceID.String()
		}
		if err := c.Roles().UnassignFromGroup(ctx, roleID, groupID, resourceParam); err != nil {
			return err
		}
	}

	req := bindingRequestFor(bc, res)
	assignErr := c.Roles().AssignToGroup(ctx, roleID, AssignRoleToGroupRequest{
		GroupID: groupID, ResourceID: req.resourceID, Inherit: req.inherit, TenantScope: req.tenantScope,
	})
	if assignErr == nil {
		return nil
	}
	if bc.previous == nil {
		return assignErr
	}
	restore := restoreRequestFor(bc)
	restoreErr := c.Roles().AssignToGroup(ctx, roleID, AssignRoleToGroupRequest{
		GroupID: groupID, ResourceID: restore.resourceID, Inherit: restore.inherit, TenantScope: restore.tenantScope,
	})
	return &rebindFailure{assignErr: assignErr, restoreErr: restoreErr}
}

// runServiceAccountBinding mirrors runUserBinding for a service-account subject.
func (a *ManifestAPI) runServiceAccountBinding(ctx context.Context, bc bindingChange, res *resolved) error {
	c := a.c
	roleID, saID := res.roles[bc.roleKey], res.serviceAccounts[bc.subjectKey]

	if bc.previous != nil {
		resourceParam := ""
		if bc.previous.resourceID != nil {
			resourceParam = bc.previous.resourceID.String()
		}
		if err := c.Roles().UnassignFromServiceAccount(ctx, roleID, saID, resourceParam); err != nil {
			return err
		}
	}

	req := bindingRequestFor(bc, res)
	assignErr := c.Roles().AssignToServiceAccount(ctx, roleID, AssignRoleToServiceAccountRequest{
		ServiceAccountID: saID, ResourceID: req.resourceID, Inherit: req.inherit, TenantScope: req.tenantScope,
	})
	if assignErr == nil {
		return nil
	}
	if bc.previous == nil {
		return assignErr
	}
	restore := restoreRequestFor(bc)
	restoreErr := c.Roles().AssignToServiceAccount(ctx, roleID, AssignRoleToServiceAccountRequest{
		ServiceAccountID: saID, ResourceID: restore.resourceID, Inherit: restore.inherit, TenantScope: restore.tenantScope,
	})
	return &rebindFailure{assignErr: assignErr, restoreErr: restoreErr}
}
