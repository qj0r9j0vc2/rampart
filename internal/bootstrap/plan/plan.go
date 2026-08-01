// Package plan implements spec section 6.6: a deterministic list of AWS
// create/update operations, computed by comparing generated artifacts
// against the live state inspect.Inspect already read — without writing
// anything. Operation order follows spec section 16.2's apply order
// (steps 5-11; steps 1-4 are the read/audit stages earlier in this
// stack, and steps 12-13 are post-apply verification, not part of a
// plan).
package plan

import (
	"fmt"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/audit"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/inspect"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

// OperationType is what a Plan step would do.
type OperationType string

const (
	Create OperationType = "create"
	Update OperationType = "update"
)

// Operation is one planned AWS write.
type Operation struct {
	Resource    string
	Type        OperationType
	Description string
}

// Plan is the full ordered list of operations apply would perform.
type Plan struct {
	Operations []Operation
}

// IsEmpty reports whether applying this plan would change anything.
// Re-running Plan against an already-converged bootstrap (spec's exit
// criterion for this milestone) must return an empty Plan.
func (p Plan) IsEmpty() bool {
	return len(p.Operations) == 0
}

// Artifacts bundles the generated documents Plan compares live state
// against.
type Artifacts struct {
	DeployPolicy     render.Document
	DeployBoundary   render.Document
	WorkloadBoundary render.Document
	TrustPolicy      render.TrustDocument
	AssumeRolePolicy render.Document
}

// Compute builds the plan. Every step is a pure function of (cfg, state,
// artifacts) — same inputs always produce the same plan, and a
// converged bootstrap (live state already matches every artifact)
// produces an empty one.
func Compute(cfg *config.Config, state inspect.LiveState, artifacts Artifacts) (Plan, error) {
	var ops []Operation

	steps := []func() (*Operation, error){
		func() (*Operation, error) {
			return planPolicyDocument("workload-boundary.json", state.WorkloadBoundaryDocument, artifacts.WorkloadBoundary)
		},
		func() (*Operation, error) {
			return planPolicyDocument("deploy-boundary.json", state.DeployBoundaryDocument, artifacts.DeployBoundary)
		},
		func() (*Operation, error) {
			return planPolicyDocument("deploy-policy.json", state.DeployPolicyDocument, artifacts.DeployPolicy)
		},
		func() (*Operation, error) {
			return planDeployRole(state, artifacts.TrustPolicy)
		},
		func() (*Operation, error) {
			return planBoundaryAttachment(cfg, state), nil
		},
		func() (*Operation, error) {
			return planPolicyAttachment(cfg, state), nil
		},
		func() (*Operation, error) {
			return planPolicyDocument("assume-role-policy.json", state.SourcePrincipalPolicyDocument, artifacts.AssumeRolePolicy)
		},
	}

	for _, step := range steps {
		op, err := step()
		if err != nil {
			return Plan{}, err
		}

		if op != nil {
			ops = append(ops, *op)
		}
	}

	return Plan{Operations: ops}, nil
}

// planPolicyDocument creates a standalone managed policy that doesn't
// exist yet, or updates it if the live document differs from what's
// generated. Reuses audit.DocumentDrift's live-vs-generated comparison
// purely for "do these differ at all" — the expansion/reduction
// classification doesn't matter for planning, only presence of a
// difference does.
func planPolicyDocument(name, liveJSON string, generated render.Document) (*Operation, error) {
	if liveJSON == "" {
		return &Operation{Resource: name, Type: Create, Description: "create " + name}, nil
	}

	result, err := audit.DocumentDrift(name, liveJSON, generated)
	if err != nil {
		return nil, err
	}

	if len(result.Changes) == 0 {
		return nil, nil
	}

	return &Operation{
		Resource:    name,
		Type:        Update,
		Description: fmt.Sprintf("update %s (%d change(s))", name, len(result.Changes)),
	}, nil
}

// planDeployRole creates the deploy role if it doesn't exist, or
// updates its trust policy if the live one differs from what's
// generated. The role's own existence and its trust policy are one
// resource in IAM (a role always has exactly one trust policy), so this
// covers both apply-order steps 8 (create/update the role) and the
// trust-policy half of what step 13 would later verify.
func planDeployRole(state inspect.LiveState, trustPolicy render.TrustDocument) (*Operation, error) {
	if state.DeployRole == nil {
		return &Operation{Resource: "deploy-role", Type: Create, Description: "create the deploy role"}, nil
	}

	result, err := audit.TrustPolicyDrift(state.DeployRole.AssumeRolePolicyDocument, trustPolicy)
	if err != nil {
		return nil, err
	}

	if len(result.Changes) == 0 {
		return nil, nil
	}

	return &Operation{
		Resource:    "deploy-role",
		Type:        Update,
		Description: fmt.Sprintf("update the deploy role's trust policy (%d change(s))", len(result.Changes)),
	}, nil
}

// planBoundaryAttachment attaches the deploy boundary as the deploy
// role's permissions boundary if it isn't already (apply-order step 9).
// Nothing to do before the role itself exists — that's planDeployRole's
// job, and this step becomes actionable on the next Plan run once it
// has.
func planBoundaryAttachment(cfg *config.Config, state inspect.LiveState) *Operation {
	if state.DeployRole == nil {
		return nil
	}

	want := policyARN(cfg, cfg.Policies.DeployBoundary.Path, cfg.Policies.DeployBoundary.Name)
	if state.DeployRole.PermissionsBoundaryARN == want {
		return nil
	}

	return &Operation{
		Resource:    "deploy-role-boundary-attachment",
		Type:        Update,
		Description: "attach " + want + " as the deploy role's permissions boundary",
	}
}

// planPolicyAttachment attaches the deploy policy to the deploy role if
// it isn't already (apply-order step 10). inspect.Inspect only
// populates DeployPolicyDocument when a policy matching config's
// expected ARN is actually found attached, so a non-empty value here
// already means "attached."
func planPolicyAttachment(cfg *config.Config, state inspect.LiveState) *Operation {
	if state.DeployRole == nil || state.DeployPolicyDocument != "" {
		return nil
	}

	want := policyARN(cfg, cfg.Policies.Deploy.Path, cfg.Policies.Deploy.Name)

	return &Operation{
		Resource:    "deploy-policy-attachment",
		Type:        Create,
		Description: "attach " + want + " to the deploy role",
	}
}

func policyARN(cfg *config.Config, path, name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:policy%s%s", cfg.AWS.Partition, cfg.AWS.AccountID, path, name)
}
