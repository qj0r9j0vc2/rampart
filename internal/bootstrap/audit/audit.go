// Package audit implements the three spec section 17.1 blocking rules
// that need live AWS state to check — RMP-E010 (managed-path role
// audit), RMP-E011 (apply caller is the deploy role) and RMP-E012
// (account mismatch) — plus boundary-drift detection (spec section
// 6.5's "boundary drift" inspect check), using the semantic diff engine
// against a freshly re-parsed live policy document. These were
// explicitly deferred out of the M1 validate package because they need
// an inspect.LiveState to check against, which only exists once the
// AWS read layer (this stack's earlier branches) is built.
package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/diff"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/inspect"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/validate"
)

// CheckAccountMatch covers RMP-E012: the configured account must match
// the account the caller's credentials actually resolve to.
func CheckAccountMatch(cfg *config.Config, state inspect.LiveState) []validate.Finding {
	if cfg.AWS.AccountID == state.Account {
		return nil
	}

	return []validate.Finding{{
		Code:     "RMP-E012",
		Severity: validate.Blocking,
		Message:  fmt.Sprintf("configured aws.account_id %s differs from the STS caller's account %s", cfg.AWS.AccountID, state.Account),
	}}
}

// CheckApplyCallerIsNotDeployRole covers RMP-E011: apply must not be
// invoked using the deploy role it would itself modify. An STS-assumed
// session of a role shows up in the caller ARN as
// "arn:...:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION", distinct from
// the role's own "arn:...:iam::ACCOUNT:role/PATH/ROLE-NAME" — so the
// check is a name match against that assumed-role marker, not an exact
// ARN comparison.
func CheckApplyCallerIsNotDeployRole(state inspect.LiveState) []validate.Finding {
	if state.DeployRole == nil {
		return nil
	}

	marker := ":assumed-role/" + state.DeployRole.Name + "/"
	if !strings.Contains(state.CallerARN, marker) {
		return nil
	}

	return []validate.Finding{{
		Code:     "RMP-E011",
		Severity: validate.Blocking,
		Message:  fmt.Sprintf("caller %s is an assumed session of the deploy role being modified", state.CallerARN),
	}}
}

// CheckManagedPathRoles covers RMP-E010: every role under
// managed_roles.path must carry the configured workload boundary.
func CheckManagedPathRoles(cfg *config.Config, state inspect.LiveState) []validate.Finding {
	want := policyARN(cfg, cfg.Policies.WorkloadBoundary.Path, cfg.Policies.WorkloadBoundary.Name)

	var findings []validate.Finding

	for _, role := range state.ManagedPathRoles {
		if role.PermissionsBoundaryARN == want {
			continue
		}

		got := role.PermissionsBoundaryARN
		if got == "" {
			got = "(none)"
		}

		findings = append(findings, validate.Finding{
			Code:     "RMP-E010",
			Severity: validate.Blocking,
			Message:  fmt.Sprintf("role %s under the managed path has permissions boundary %s, want %s", role.ARN, got, want),
		})
	}

	return findings
}

// DocumentDrift re-parses a live policy document (as read by
// inspect.Inspect, already URL-decoded) and diffs it against the
// freshly generated version using the semantic diff engine.
//
// generated is passed as the diff engine's "old"/baseline side and live
// as "new": drift asks "how does the live resource differ from what we
// intend", not "how would applying change it". Getting this order
// backwards silently inverts every classification — e.g. live missing a
// condition the generated document requires would classify as
// "condition tightening" (a good change) instead of the security
// problem it actually is. A caught-during-review regression test
// (TestDocumentDrift/TestTrustPolicyDrift) pins this down.
//
// An empty liveJSON (the resource doesn't exist yet) isn't drift —
// there's nothing to have drifted from — so it returns an empty Result
// rather than an error.
func DocumentDrift(name, liveJSON string, generated render.Document) (diff.Result, error) {
	if liveJSON == "" {
		return diff.Result{Name: name}, nil
	}

	var live render.Document
	if err := json.Unmarshal([]byte(liveJSON), &live); err != nil {
		return diff.Result{}, fmt.Errorf("parsing live %s: %w", name, err)
	}

	return diff.DiffDocument(name, generated, live), nil
}

// TrustPolicyDrift is DocumentDrift for the Principal-based trust policy
// shape (render.TrustDocument), which DiffDocument can't compare.
func TrustPolicyDrift(liveJSON string, generated render.TrustDocument) (diff.Result, error) {
	if liveJSON == "" {
		return diff.Result{Name: "trust-policy.json"}, nil
	}

	var live render.TrustDocument
	if err := json.Unmarshal([]byte(liveJSON), &live); err != nil {
		return diff.Result{}, fmt.Errorf("parsing live trust-policy.json: %w", err)
	}

	return diff.DiffTrustPolicy(generated, live), nil
}

func policyARN(cfg *config.Config, path, name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:policy%s%s", cfg.AWS.Partition, cfg.AWS.AccountID, path, name)
}
