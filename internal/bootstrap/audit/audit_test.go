package audit_test

import (
	"testing"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/audit"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/inspect"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

func testConfig() *config.Config {
	return &config.Config{
		AWS:          config.AWSConfig{AccountID: "123456789012", Partition: "aws"},
		ManagedRoles: config.ManagedRolesConfig{Path: "/terraform-managed/"},
		Policies: config.PoliciesConfig{
			WorkloadBoundary: config.WorkloadBoundaryConfig{Name: "TerraformWorkloadBoundary", Path: "/boundaries/"},
		},
	}
}

const workloadBoundaryARN = "arn:aws:iam::123456789012:policy/boundaries/TerraformWorkloadBoundary"

func TestCheckAccountMatch(t *testing.T) {
	t.Parallel()

	cfg := testConfig()

	if findings := audit.CheckAccountMatch(cfg, inspect.LiveState{Account: "123456789012"}); len(findings) != 0 {
		t.Errorf("CheckAccountMatch() = %+v, want none for a matching account", findings)
	}

	findings := audit.CheckAccountMatch(cfg, inspect.LiveState{Account: "999999999999"})
	if len(findings) != 1 || findings[0].Code != "RMP-E012" {
		t.Errorf("CheckAccountMatch() = %+v, want one RMP-E012 finding", findings)
	}
}

func TestCheckApplyCallerIsNotDeployRole(t *testing.T) {
	t.Parallel()

	deployRole := &inspect.Role{Name: "TerraformDeployRole", ARN: "arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole"}

	tests := []struct {
		name      string
		callerARN string
		wantCode  string
	}{
		{"bootstrap administrator caller is fine", "arn:aws:iam::123456789012:user/admin", ""},
		{"assumed session of the deploy role is blocked", "arn:aws:sts::123456789012:assumed-role/TerraformDeployRole/terraform-session", "RMP-E011"},
		{"a different role's assumed session is fine", "arn:aws:sts::123456789012:assumed-role/SomeOtherRole/session", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := audit.CheckApplyCallerIsNotDeployRole(inspect.LiveState{CallerARN: tt.callerARN, DeployRole: deployRole})

			if tt.wantCode == "" {
				if len(findings) != 0 {
					t.Errorf("CheckApplyCallerIsNotDeployRole() = %+v, want none", findings)
				}

				return
			}

			if len(findings) != 1 || findings[0].Code != tt.wantCode {
				t.Errorf("CheckApplyCallerIsNotDeployRole() = %+v, want one %s finding", findings, tt.wantCode)
			}
		})
	}
}

func TestCheckApplyCallerIsNotDeployRole_NoDeployRoleYet(t *testing.T) {
	t.Parallel()

	// Nothing to check against before the deploy role even exists.
	findings := audit.CheckApplyCallerIsNotDeployRole(inspect.LiveState{CallerARN: "arn:aws:iam::123456789012:user/admin", DeployRole: nil})
	if len(findings) != 0 {
		t.Errorf("CheckApplyCallerIsNotDeployRole() = %+v, want none", findings)
	}
}

func TestCheckManagedPathRoles(t *testing.T) {
	t.Parallel()

	cfg := testConfig()

	state := inspect.LiveState{ManagedPathRoles: []inspect.Role{
		{ARN: "arn:...role/terraform-managed/good", PermissionsBoundaryARN: workloadBoundaryARN},
		{ARN: "arn:...role/terraform-managed/wrong-boundary", PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/boundaries/SomeOtherBoundary"},
		{ARN: "arn:...role/terraform-managed/no-boundary", PermissionsBoundaryARN: ""},
	}}

	findings := audit.CheckManagedPathRoles(cfg, state)
	if len(findings) != 2 {
		t.Fatalf("CheckManagedPathRoles() = %+v, want 2 findings (wrong-boundary and no-boundary)", findings)
	}

	for _, f := range findings {
		if f.Code != "RMP-E010" {
			t.Errorf("Code = %q, want RMP-E010", f.Code)
		}
	}
}

func TestCheckManagedPathRoles_AllSafe(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	state := inspect.LiveState{ManagedPathRoles: []inspect.Role{
		{ARN: "arn:...role/terraform-managed/a", PermissionsBoundaryARN: workloadBoundaryARN},
		{ARN: "arn:...role/terraform-managed/b", PermissionsBoundaryARN: workloadBoundaryARN},
	}}

	if findings := audit.CheckManagedPathRoles(cfg, state); len(findings) != 0 {
		t.Errorf("CheckManagedPathRoles() = %+v, want none", findings)
	}
}

// TestDocumentDrift_LiveHasExtraPermission is the core drift scenario:
// something (a manual console edit, say) added an action to the live
// boundary that the generated boundary doesn't grant. That must
// classify as an expansion relative to intent — live now allows more
// than Rampart says it should — regardless of which side of the diff
// happens to have fewer statements.
func TestDocumentDrift_LiveHasExtraPermission(t *testing.T) {
	t.Parallel()

	generated := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
	}}
	live := `{"Version":"2012-10-17","Statement":[{"Sid":"IAMRead","Effect":"Allow","Action":["iam:GetRole","iam:ListRolePolicies"],"Resource":["*"]}]}`

	result, err := audit.DocumentDrift("deploy-boundary.json", live, generated)
	if err != nil {
		t.Fatalf("DocumentDrift() error = %v", err)
	}

	if !result.RequiresApproval() {
		t.Fatalf("RequiresApproval() = false, want true — live grants iam:ListRolePolicies that generated doesn't, changes: %+v", result.Changes)
	}

	found := false

	for _, c := range result.Changes {
		if c.Kind == "permission-expansion" {
			found = true
		}
	}

	if !found {
		t.Errorf("Changes = %+v, want a permission-expansion entry for the action live has beyond what's generated", result.Changes)
	}
}

// TestDocumentDrift_LiveMissingPermission is the opposite direction:
// live grants less than generated calls for (e.g. apply hasn't caught
// up yet, or something removed an action). That's a reduction relative
// to intent, not a security concern requiring approval.
func TestDocumentDrift_LiveMissingPermission(t *testing.T) {
	t.Parallel()

	generated := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole", "iam:ListRolePolicies"}, Resource: []string{"*"}},
	}}
	live := `{"Version":"2012-10-17","Statement":[{"Sid":"IAMRead","Effect":"Allow","Action":["iam:GetRole"],"Resource":["*"]}]}`

	result, err := audit.DocumentDrift("deploy-boundary.json", live, generated)
	if err != nil {
		t.Fatalf("DocumentDrift() error = %v", err)
	}

	if result.RequiresApproval() {
		t.Errorf("RequiresApproval() = true, want false — live granting less than intended isn't a security concern, changes: %+v", result.Changes)
	}
}

func TestDocumentDrift_NothingLiveYetIsNotDrift(t *testing.T) {
	t.Parallel()

	generated := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
	}}

	result, err := audit.DocumentDrift("workload-boundary.json", "", generated)
	if err != nil {
		t.Fatalf("DocumentDrift() error = %v", err)
	}

	if len(result.Changes) != 0 {
		t.Errorf("Changes = %+v, want none — nothing live yet isn't drift, it's just not-applied-yet", result.Changes)
	}
}

func TestDocumentDrift_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := audit.DocumentDrift("deploy-boundary.json", "{not json", render.Document{})
	if err == nil {
		t.Fatal("DocumentDrift() error = nil, want a parse error surfaced")
	}
}

func TestTrustPolicyDrift(t *testing.T) {
	t.Parallel()

	live := `{"Version":"2012-10-17","Statement":[{"Sid":"AssumeWithMFA","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/cli-user"},"Action":"sts:AssumeRole"}]}`
	generated := render.TrustDocument{Statement: []render.TrustStatement{{
		Sid: "AssumeWithMFA", Effect: "Allow",
		Principal: map[string]string{"AWS": "arn:aws:iam::123456789012:user/cli-user"},
		Action:    "sts:AssumeRole",
		Condition: &render.TrustCondition{Bool: map[string]string{"aws:MultiFactorAuthPresent": "true"}},
	}}}

	result, err := audit.TrustPolicyDrift(live, generated)
	if err != nil {
		t.Fatalf("TrustPolicyDrift() error = %v", err)
	}

	if !result.RequiresApproval() {
		t.Error("RequiresApproval() = false, want true — the live trust policy has no MFA condition the generated one requires")
	}
}
