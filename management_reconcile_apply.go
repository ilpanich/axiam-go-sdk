package axiam

import (
	"context"
	"fmt"
	"strings"
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
		if err := a.run(ctx, planned.step, res); err != nil {
			report.Steps = append(report.Steps, AppliedStep{
				Action:  planned.action,
				Outcome: StepOutcome{Status: StatusFailed, Message: err.Error()},
			})
			stopped = true
			continue
		}
		status := StatusCreated
		if strings.HasPrefix(string(planned.step.kind), "update") {
			status = StatusUpdated
		}
		report.Steps = append(report.Steps, AppliedStep{
			Action: planned.action, Outcome: StepOutcome{Status: status},
		})
	}
	return report, nil
}

// run carries out one step, recording any id it mints.
func (a *ManifestAPI) run(ctx context.Context, s step, res *resolved) error {
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
		created, err := c.Resources().Create(ctx, body)
		if err != nil {
			return err
		}
		res.resources[s.key] = created.ID
		return nil

	case stepUpdateResource:
		spec := s.spec.(ResourceSpec)
		_, err := c.Resources().Update(ctx, res.resources[s.key],
			UpdateResourceRequest{ResourceType: ptr(spec.ResourceType)})
		return err

	case stepCreateScope:
		spec := s.spec.(ScopeSpec)
		created, err := c.Scopes().Create(ctx, res.resources[s.related],
			CreateScopeRequest{Name: spec.Name, Description: spec.Description})
		if err != nil {
			return err
		}
		res.scopes[s.key] = created.ID
		return nil

	case stepCreatePermission:
		spec := s.spec.(PermissionSpec)
		created, err := c.Permissions().Create(ctx,
			CreatePermissionRequest{Action: spec.Action, Description: spec.Description})
		if err != nil {
			return err
		}
		res.permissions[s.key] = created.ID
		return nil

	case stepUpdatePermission:
		spec := s.spec.(PermissionSpec)
		_, err := c.Permissions().Update(ctx, res.permissions[s.key],
			UpdatePermissionRequest{Description: ptr(spec.Description)})
		return err

	case stepCreateRole:
		spec := s.spec.(RoleSpec)
		created, err := c.Roles().Create(ctx, CreateRoleRequest{
			Name: spec.Name, Description: spec.Description, IsGlobal: spec.IsGlobal,
		})
		if err != nil {
			return err
		}
		res.roles[s.key] = created.ID
		return nil

	case stepUpdateRole:
		spec := s.spec.(RoleSpec)
		_, err := c.Roles().Update(ctx, res.roles[s.key], UpdateRole{
			Description: ptr(spec.Description), IsGlobal: ptr(spec.IsGlobal),
		})
		return err

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
		return c.Roles().GrantPermission(ctx, res.roles[s.related], body)

	case stepCreateGroup:
		spec := s.spec.(GroupSpec)
		created, err := c.Groups().Create(ctx,
			CreateGroupRequest{Name: spec.Name, Description: spec.Description})
		if err != nil {
			return err
		}
		res.groups[s.key] = created.ID
		return nil

	case stepUpdateGroup:
		spec := s.spec.(GroupSpec)
		_, err := c.Groups().Update(ctx, res.groups[s.key],
			UpdateGroup{Description: ptr(spec.Description)})
		return err

	case stepAssignRoleToGroup:
		roleKey := s.spec.(string)
		return c.Roles().AssignToGroup(ctx, res.roles[roleKey],
			AssignRoleToGroupRequest{GroupID: res.groups[s.related]})

	case stepCreateUser:
		spec := s.spec.(UserSpec)
		created, err := c.Users().Create(ctx, CreateUserRequest{
			Username: spec.Username, Email: spec.Email, Password: spec.InitialPassword,
		})
		if err != nil {
			return err
		}
		res.users[s.key] = created.ID
		return nil

	case stepUpdateUser:
		spec := s.spec.(UserSpec)
		_, err := c.Users().Update(ctx, res.users[s.key],
			UpdateUserRequest{Email: ptr(spec.Email)})
		return err

	case stepAssignRoleToUser:
		roleKey := s.spec.(string)
		return c.Roles().AssignToUser(ctx, res.roles[roleKey],
			AssignRoleToUserRequest{UserID: res.users[s.related]})

	case stepAddGroupMember:
		groupKey := s.spec.(string)
		return c.Groups().AddMember(ctx, res.groups[groupKey],
			AddMemberRequest{UserID: res.users[s.related]})
	}
	// Unreachable: computeSteps emits only the kinds above.
	return &NetworkError{Message: fmt.Sprintf("unknown manifest step %q", s.kind)}
}
