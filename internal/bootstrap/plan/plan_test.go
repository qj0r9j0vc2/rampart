package plan_test

import (
	"encoding/json"
	"testing"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/inspect"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/plan"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

func testConfig() *config.Config {
	return &config.Config{
		AWS:        config.AWSConfig{AccountID: "123456789012", Partition: "aws"},
		DeployRole: config.DeployRoleConfig{Name: "TerraformDeployRole", Path: "/terraform-deploy/"},
		Policies: config.PoliciesConfig{
			Deploy:           config.PolicyConfig{Name: "TerraformDeployPolicy", Path: "/terraform-deploy/"},
			DeployBoundary:   config.PolicyConfig{Name: "TerraformDeployBoundary", Path: "/boundaries/"},
			WorkloadBoundary: config.WorkloadBoundaryConfig{Name: "TerraformWorkloadBoundary", Path: "/boundaries/"},
		},
	}
}

const (
	deployBoundaryARN = "arn:aws:iam::123456789012:policy/boundaries/TerraformDeployBoundary"
)

func testArtifacts() plan.Artifacts {
	return plan.Artifacts{
		WorkloadBoundary: render.Document{Statements: []render.Statement{
			{Sid: "TerraformWorkloadBoundary", Effect: "Allow", Action: []string{"logs:PutLogEvents"}, Resource: []string{"*"}},
		}},
		DeployBoundary: render.Document{Statements: []render.Statement{
			{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
		}},
		DeployPolicy: render.Document{Statements: []render.Statement{
			{Sid: "DeployPolicy0", Effect: "Allow", Action: []string{"ec2:DescribeInstances"}, Resource: []string{"*"}},
		}},
		TrustPolicy: render.TrustDocument{Statement: []render.TrustStatement{{
			Sid: "AssumeWithMFA", Effect: "Allow", Principal: map[string]string{"AWS": "arn:aws:iam::123456789012:user/cli-user"}, Action: "sts:AssumeRole",
		}}},
		AssumeRolePolicy: render.Document{Statements: []render.Statement{
			{Sid: "AssumeTerraformDeployRole", Effect: "Allow", Action: []string{"sts:AssumeRole"}, Resource: []string{"arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole"}},
		}},
	}
}

// canonicalJSON renders a render.Document/TrustDocument the same way
// inspect.Inspect would have read it back from AWS: as the exact JSON
// bytes of the generated artifact, so a "converged" fixture is
// byte-equivalent to what Plan should treat as already up to date.
func canonicalJSON(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestCompute_ConvergedStateIsEmptyPlan(t *testing.T) {
	t.Parallel()

	artifacts := testArtifacts()

	state := inspect.LiveState{
		DeployRole: &inspect.Role{
			ARN: "arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole", Name: "TerraformDeployRole",
			AssumeRolePolicyDocument: canonicalJSON(t, artifacts.TrustPolicy),
			PermissionsBoundaryARN:   deployBoundaryARN,
		},
		WorkloadBoundaryDocument:      canonicalJSON(t, artifacts.WorkloadBoundary),
		DeployBoundaryDocument:        canonicalJSON(t, artifacts.DeployBoundary),
		DeployPolicyDocument:          canonicalJSON(t, artifacts.DeployPolicy),
		SourcePrincipalPolicyDocument: canonicalJSON(t, artifacts.AssumeRolePolicy),
	}

	p, err := plan.Compute(testConfig(), state, artifacts)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	if !p.IsEmpty() {
		t.Fatalf("Compute() = %+v, want an empty plan for an already-converged bootstrap (spec's re-run exit criterion)", p.Operations)
	}
}

func TestCompute_NothingExistsYet(t *testing.T) {
	t.Parallel()

	p, err := plan.Compute(testConfig(), inspect.LiveState{}, testArtifacts())
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	wantOrder := []string{
		"workload-boundary.json",
		"deploy-boundary.json",
		"deploy-policy.json",
		"deploy-role",
		"assume-role-policy.json",
	}

	if len(p.Operations) != len(wantOrder) {
		t.Fatalf("Compute() = %+v, want %d operations (attachments have nothing to attach to before the role exists)", p.Operations, len(wantOrder))
	}

	for i, want := range wantOrder {
		if p.Operations[i].Resource != want {
			t.Errorf("Operations[%d].Resource = %q, want %q (apply-order steps must stay in order)", i, p.Operations[i].Resource, want)
		}

		if p.Operations[i].Type != plan.Create {
			t.Errorf("Operations[%d].Type = %q, want create", i, p.Operations[i].Type)
		}
	}
}

// TestCompute_RoleExistsBoundaryNotAttached isolates the single gap
// where the deploy role and every managed policy already exist and
// match, but the deploy boundary isn't attached yet as the role's
// permissions boundary — the one attachment inspect.LiveState can
// represent independently of "does the policy exist" (unlike the
// deploy-policy attachment: inspect.Inspect only populates
// DeployPolicyDocument when it finds a matching policy already attached
// to the role, so "exists but unattached" isn't representable there —
// see the package doc comment on inspect.LiveState).
func TestCompute_RoleExistsBoundaryNotAttached(t *testing.T) {
	t.Parallel()

	artifacts := testArtifacts()

	state := inspect.LiveState{
		DeployRole: &inspect.Role{
			ARN: "arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole", Name: "TerraformDeployRole",
			AssumeRolePolicyDocument: canonicalJSON(t, artifacts.TrustPolicy),
			// No PermissionsBoundaryARN yet — this is the one gap.
		},
		WorkloadBoundaryDocument:      canonicalJSON(t, artifacts.WorkloadBoundary),
		DeployBoundaryDocument:        canonicalJSON(t, artifacts.DeployBoundary),
		DeployPolicyDocument:          canonicalJSON(t, artifacts.DeployPolicy),
		SourcePrincipalPolicyDocument: canonicalJSON(t, artifacts.AssumeRolePolicy),
	}

	p, err := plan.Compute(testConfig(), state, artifacts)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	if len(p.Operations) != 1 {
		t.Fatalf("Compute() = %+v, want exactly one operation (the boundary attachment)", p.Operations)
	}

	if p.Operations[0].Resource != "deploy-role-boundary-attachment" || p.Operations[0].Type != plan.Update {
		t.Errorf("Operations[0] = %+v, want an update to deploy-role-boundary-attachment", p.Operations[0])
	}
}

func TestCompute_DriftedDeployBoundaryProducesUpdate(t *testing.T) {
	t.Parallel()

	artifacts := testArtifacts()

	driftedBoundary := `{"Version":"2012-10-17","Statement":[{"Sid":"IAMRead","Effect":"Allow","Action":["iam:GetRole","iam:PassRole"],"Resource":["*"]}]}`

	state := inspect.LiveState{
		DeployRole: &inspect.Role{
			Name:                     "TerraformDeployRole",
			AssumeRolePolicyDocument: canonicalJSON(t, artifacts.TrustPolicy),
			PermissionsBoundaryARN:   deployBoundaryARN,
		},
		WorkloadBoundaryDocument:      canonicalJSON(t, artifacts.WorkloadBoundary),
		DeployBoundaryDocument:        driftedBoundary,
		DeployPolicyDocument:          canonicalJSON(t, artifacts.DeployPolicy),
		SourcePrincipalPolicyDocument: canonicalJSON(t, artifacts.AssumeRolePolicy),
	}

	p, err := plan.Compute(testConfig(), state, artifacts)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	if len(p.Operations) != 1 {
		t.Fatalf("Compute() = %+v, want exactly one update operation", p.Operations)
	}

	if p.Operations[0].Resource != "deploy-boundary.json" || p.Operations[0].Type != plan.Update {
		t.Errorf("Operations[0] = %+v, want an update to deploy-boundary.json", p.Operations[0])
	}
}

func TestCompute_InvalidLiveJSONPropagatesError(t *testing.T) {
	t.Parallel()

	state := inspect.LiveState{DeployBoundaryDocument: "{not valid json"}

	if _, err := plan.Compute(testConfig(), state, testArtifacts()); err == nil {
		t.Fatal("Compute() error = nil, want the JSON parse failure surfaced")
	}
}

func TestCompute_Deterministic(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	state := inspect.LiveState{}
	artifacts := testArtifacts()

	first, err := plan.Compute(cfg, state, artifacts)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		p, err := plan.Compute(cfg, state, artifacts)
		if err != nil {
			t.Fatal(err)
		}

		if len(p.Operations) != len(first.Operations) {
			t.Fatalf("run %d: Compute() = %+v, want the same %d operations as the first run", i, p.Operations, len(first.Operations))
		}

		for j := range p.Operations {
			if p.Operations[j] != first.Operations[j] {
				t.Fatalf("run %d: Operations[%d] = %+v, want %+v", i, j, p.Operations[j], first.Operations[j])
			}
		}
	}
}
