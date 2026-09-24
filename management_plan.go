package axiam

// The plan a manifest reconciles to — CONTRACT.md §27.6.

// Change says whether reconciling one spec would create, update, or do nothing.
type Change string

// The three Change values.
const (
	// ChangeCreate: the thing does not exist and would be created.
	ChangeCreate Change = "create"
	// ChangeUpdate: it exists but a field the manifest states has drifted.
	ChangeUpdate Change = "update"
	// ChangeNone: it already matches.
	ChangeNone Change = "no-change"
)

// Target says which part of the manifest an action came from.
type Target string

// The Target values, one per kind of thing the reconciler acts on.
const (
	TargetResource           Target = "resource"
	TargetScope              Target = "scope"
	TargetPermission         Target = "permission"
	TargetRole               Target = "role"
	TargetRoleGrant          Target = "role-grant"
	TargetGroup              Target = "group"
	TargetGroupRole          Target = "group-role"
	TargetUser               Target = "user"
	TargetUserRole           Target = "user-role"
	TargetGroupMember        Target = "group-member"
	TargetServiceAccount     Target = "service-account"
	TargetServiceAccountRole Target = "service-account-role"
)

// Status says what actually became of one planned step.
type Status string

// The Status values.
const (
	// StatusCreated: the step ran and the thing now exists.
	StatusCreated Status = "created"
	// StatusUpdated: the step ran and the thing was updated.
	StatusUpdated Status = "updated"
	// StatusUnchanged: a no-op step; nothing was sent.
	StatusUnchanged Status = "unchanged"
	// StatusFailed: the step failed. Everything before it has already happened.
	StatusFailed Status = "failed"
	// StatusNotAttempted: never attempted, because an earlier step failed.
	StatusNotAttempted Status = "not-attempted"
	// StatusRestored: a role-binding rebind's "assign the new binding"
	// half failed, and the previous binding (same resource, same inherit)
	// was successfully re-assigned (§27.6.1: "If the assign fails, the SDK
	// MUST attempt to assign the previous binding again ... and report
	// both outcomes"). This status appears on a SYNTHETIC step immediately
	// after the StatusFailed rebind step it restores.
	StatusRestored Status = "restored"
	// StatusRestoreFailed: the rebind's restore attempt ALSO failed. The
	// subject may now hold neither the old nor the new binding — Message
	// carries the restore attempt's own error, and the preceding
	// StatusFailed step's Message carries the original assign failure.
	StatusRestoreFailed Status = "restore-failed"
)

// PlannedAction is one step of a plan.
type PlannedAction struct {
	// Change is whether this step creates, updates, or does nothing.
	Change Change
	// Target is what kind of thing it acts on.
	Target Target
	// Key is the manifest key it came from, for a human reading the plan.
	Key string
	// Summary is a one-line description, stable across runs so plans diff.
	Summary string
}

// ManagementPlan is the ordered set of actions that would reconcile a manifest.
//
// Ordering is derived, not incidental: resources (parents before children),
// then scopes, permissions, roles, role grants, groups, group bindings, users,
// and finally the user bindings that need all of the above to exist. Two plans
// over unchanged state are equal, in the same order (§27.6 rule 8) — a plan
// that reorders between runs cannot be diffed, and diffing it is most of the
// reason it exists.
type ManagementPlan struct {
	// Actions is every step, including the no-ops.
	Actions []PlannedAction
}

// Changes returns the steps of this plan that would actually change something.
func (p ManagementPlan) Changes() []PlannedAction {
	var out []PlannedAction
	for _, a := range p.Actions {
		if a.Change != ChangeNone {
			out = append(out, a)
		}
	}
	return out
}

// IsConverged reports whether applying this plan would change nothing.
//
// This is the §27.6 rule 6 acceptance test: Apply then Plan must land here, or
// the SDK has a drift-detection bug.
func (p ManagementPlan) IsConverged() bool { return len(p.Changes()) == 0 }

// StepOutcome is what actually happened to one planned step.
type StepOutcome struct {
	// Status is created, updated, unchanged, failed, not-attempted,
	// restored or restore-failed.
	Status Status
	// Message is the error the server or transport gave, on a failed
	// (or restore-failed) step only.
	Message string
	// CreatedServiceAccount is set ONLY on a StatusCreated step whose
	// Action.Target is TargetServiceAccount: the FULL response the
	// server's Create returned, client_secret included (§27.5 rule 5).
	// This is the only place that secret exists — get/list never return
	// it again — so it is carried here rather than summarised away, and
	// carried even when a LATER step of the same Apply fails (§27.6 rule
	// 7's "every attempted action's outcome" is what makes that true: this
	// step's own outcome is recorded before any later step runs).
	CreatedServiceAccount *ServiceAccountCreatedResponse
}

// AppliedStep is one planned step paired with what became of it.
type AppliedStep struct {
	// Action is the step, exactly as Plan reported it.
	Action PlannedAction
	// Outcome is what actually happened when it ran — or did not.
	Outcome StepOutcome
}

// ManifestFailure is the step that stopped an apply, and why.
type ManifestFailure struct {
	// Action is the step that failed. Everything before it has happened.
	Action PlannedAction
	// Message is the error the server or transport gave.
	Message string
}

// ApplyReport is the result of applying a manifest.
//
// THERE IS NO TRANSACTION HERE AND THIS TYPE DOES NOT PRETEND THERE IS
// (§27.6 rule 7). These are independent HTTP endpoints; nothing spans them. If
// step 12 of 30 fails, steps 1–11 have happened and will not be undone — so
// every step's outcome is reported, execution stops at the first failure rather
// than continuing blindly, and there is no Rollback because this SDK could not
// honour one. Fix the cause and re-apply: rule 6's idempotence is what makes
// that safe.
type ApplyReport struct {
	// Steps is each planned step paired with what became of it, in plan order.
	Steps []AppliedStep
}

// Failure returns the failing step, if the apply stopped early.
func (r ApplyReport) Failure() (ManifestFailure, bool) {
	for _, s := range r.Steps {
		if s.Outcome.Status == StatusFailed {
			return ManifestFailure{Action: s.Action, Message: s.Outcome.Message}, true
		}
	}
	return ManifestFailure{}, false
}

// IsComplete reports whether every step that was meant to run did.
func (r ApplyReport) IsComplete() bool {
	_, failed := r.Failure()
	return !failed
}

// CreatedServiceAccounts returns every StepOutcome.CreatedServiceAccount
// this Apply produced, in step order (§27.5 rule 5). A manifest with no
// ServiceAccounts section, or one whose accounts all already existed,
// returns an empty slice — never an error.
func (r ApplyReport) CreatedServiceAccounts() []ServiceAccountCreatedResponse {
	var out []ServiceAccountCreatedResponse
	for _, s := range r.Steps {
		if s.Outcome.CreatedServiceAccount != nil {
			out = append(out, *s.Outcome.CreatedServiceAccount)
		}
	}
	return out
}

// ChangedCount reports how many steps actually changed something.
func (r ApplyReport) ChangedCount() int {
	n := 0
	for _, s := range r.Steps {
		if s.Outcome.Status == StatusCreated || s.Outcome.Status == StatusUpdated {
			n++
		}
	}
	return n
}
