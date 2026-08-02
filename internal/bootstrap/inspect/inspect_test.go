package inspect_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/aws/awsfake"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/inspect"
)

func testConfig() *config.Config {
	return &config.Config{
		AWS:        config.AWSConfig{AccountID: "123456789012", Partition: "aws"},
		Principal:  config.PrincipalConfig{Type: "iam-user", Name: "cli-user"},
		DeployRole: config.DeployRoleConfig{Name: "TerraformDeployRole", Path: "/terraform-deploy/"},
		ManagedRoles: config.ManagedRolesConfig{
			Path: "/terraform-managed/",
		},
		Policies: config.PoliciesConfig{
			Deploy:           config.PolicyConfig{Name: "TerraformDeployPolicy", Path: "/terraform-deploy/"},
			DeployBoundary:   config.PolicyConfig{Name: "TerraformDeployBoundary", Path: "/boundaries/"},
			WorkloadBoundary: config.WorkloadBoundaryConfig{Name: "TerraformWorkloadBoundary", Path: "/boundaries/"},
		},
	}
}

func ptr[T any](v T) *T { return &v }

func notFound() error {
	return &types.NoSuchEntityException{Message: ptr("not found")}
}

// TestInspect_HappyPath exercises every resource existing, verifying
// LiveState is populated correctly end-to-end: caller identity, the
// source principal's MFA devices, the deploy role's decoded trust
// policy and boundary ARN, the deploy policy fetched only because its
// ARN matches what's actually attached, the workload boundary fetched
// directly, the inline source-principal policy, and every managed-path
// role collected across two pages.
func TestInspect_HappyPath(t *testing.T) {
	t.Parallel()

	deployBoundaryARN := "arn:aws:iam::123456789012:policy/boundaries/TerraformDeployBoundary"
	deployPolicyARN := "arn:aws:iam::123456789012:policy/terraform-deploy/TerraformDeployPolicy"
	workloadBoundaryARN := "arn:aws:iam::123456789012:policy/boundaries/TerraformWorkloadBoundary"

	iamClient := &awsfake.IAM{
		GetUserFunc: func(_ context.Context, params *iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{User: &types.User{Arn: ptr("arn:aws:iam::123456789012:user/cli-user")}}, nil
		},
		ListMFADevicesFunc: func(context.Context, *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{{SerialNumber: ptr("arn:aws:iam::123456789012:mfa/cli-user")}}}, nil
		},
		GetRoleFunc: func(_ context.Context, params *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{
				Arn:                      ptr("arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole"),
				RoleName:                 ptr("TerraformDeployRole"),
				Path:                     ptr("/terraform-deploy/"),
				AssumeRolePolicyDocument: ptr(url.QueryEscape(`{"Version":"2012-10-17"}`)),
				PermissionsBoundary:      &types.AttachedPermissionsBoundary{PermissionsBoundaryArn: &deployBoundaryARN},
			}}, nil
		},
		ListAttachedRolePoliciesFunc: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{
				{PolicyArn: &deployPolicyARN, PolicyName: ptr("TerraformDeployPolicy")},
			}}, nil
		},
		GetPolicyFunc: func(_ context.Context, params *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{Policy: &types.Policy{DefaultVersionId: ptr("v1")}}, nil
		},
		GetPolicyVersionFunc: func(_ context.Context, params *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			doc := `{"policy":"` + *params.PolicyArn + `"}`

			return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: ptr(url.QueryEscape(doc))}}, nil
		},
		ListUserPoliciesFunc: func(context.Context, *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
			return &iam.ListUserPoliciesOutput{PolicyNames: []string{"AssumeTerraformDeployRole"}}, nil
		},
		GetUserPolicyFunc: func(context.Context, *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
			return &iam.GetUserPolicyOutput{PolicyDocument: ptr(url.QueryEscape(`{"assume":"role"}`))}, nil
		},
		ListRolesFunc: func(_ context.Context, params *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			if params.Marker == nil {
				return &iam.ListRolesOutput{
					Roles:       []types.Role{{Arn: ptr("arn:...role/terraform-managed/a"), RoleName: ptr("a"), Path: ptr("/terraform-managed/")}},
					IsTruncated: true,
					Marker:      ptr("page2"),
				}, nil
			}

			return &iam.ListRolesOutput{
				Roles: []types.Role{{
					Arn: ptr("arn:...role/terraform-managed/b"), RoleName: ptr("b"), Path: ptr("/terraform-managed/"),
					PermissionsBoundary: &types.AttachedPermissionsBoundary{PermissionsBoundaryArn: &workloadBoundaryARN},
				}},
				IsTruncated: false,
			}, nil
		},
	}

	stsClient := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: ptr("123456789012"), Arn: ptr("arn:aws:iam::123456789012:user/bootstrap-admin")}, nil
		},
	}

	state, err := inspect.Inspect(context.Background(), testConfig(), iamClient, stsClient)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}

	if state.Account != "123456789012" {
		t.Errorf("Account = %q, want 123456789012", state.Account)
	}

	if state.CallerARN != "arn:aws:iam::123456789012:user/bootstrap-admin" {
		t.Errorf("CallerARN = %q", state.CallerARN)
	}

	if state.SourcePrincipal == nil {
		t.Fatal("SourcePrincipal = nil, want populated")
	}

	if len(state.SourcePrincipal.MFADeviceARNs) != 1 {
		t.Errorf("SourcePrincipal.MFADeviceARNs = %v, want 1 device", state.SourcePrincipal.MFADeviceARNs)
	}

	if state.DeployRole == nil {
		t.Fatal("DeployRole = nil, want populated")
	}

	if state.DeployRole.AssumeRolePolicyDocument != `{"Version":"2012-10-17"}` {
		t.Errorf("DeployRole.AssumeRolePolicyDocument = %q, want URL-decoded JSON", state.DeployRole.AssumeRolePolicyDocument)
	}

	if state.DeployRole.PermissionsBoundaryARN != deployBoundaryARN {
		t.Errorf("DeployRole.PermissionsBoundaryARN = %q, want %q", state.DeployRole.PermissionsBoundaryARN, deployBoundaryARN)
	}

	if state.DeployPolicyDocument == "" {
		t.Error("DeployPolicyDocument is empty, want the fetched (matching-ARN) attached policy document")
	}

	if state.DeployBoundaryDocument == "" {
		t.Error("DeployBoundaryDocument is empty, want the deploy role's permissions boundary document")
	}

	if state.WorkloadBoundaryDocument == "" {
		t.Error("WorkloadBoundaryDocument is empty, want it fetched directly by ARN")
	}

	if state.SourcePrincipalPolicyDocument != `{"assume":"role"}` {
		t.Errorf("SourcePrincipalPolicyDocument = %q, want URL-decoded JSON", state.SourcePrincipalPolicyDocument)
	}

	if len(state.ManagedPathRoles) != 2 {
		t.Fatalf("ManagedPathRoles = %+v, want 2 roles across both pages", state.ManagedPathRoles)
	}

	if state.ManagedPathRoles[1].PermissionsBoundaryARN != workloadBoundaryARN {
		t.Errorf("ManagedPathRoles[1].PermissionsBoundaryARN = %q, want %q", state.ManagedPathRoles[1].PermissionsBoundaryARN, workloadBoundaryARN)
	}
}

func TestInspect_SourcePrincipalMissing(t *testing.T) {
	t.Parallel()

	iamClient := &awsfake.IAM{
		GetUserFunc: func(context.Context, *iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, notFound()
		},
		GetRoleFunc: func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return nil, notFound()
		},
		GetPolicyFunc: func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			return nil, notFound()
		},
		ListRolesFunc: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{}, nil
		},
	}
	stsClient := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: ptr("123456789012"), Arn: ptr("arn:aws:iam::123456789012:user/admin")}, nil
		},
	}

	state, err := inspect.Inspect(context.Background(), testConfig(), iamClient, stsClient)
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil — a not-yet-bootstrapped account is a normal, expected state", err)
	}

	if state.SourcePrincipal != nil {
		t.Errorf("SourcePrincipal = %+v, want nil", state.SourcePrincipal)
	}

	if state.DeployRole != nil {
		t.Errorf("DeployRole = %+v, want nil", state.DeployRole)
	}

	if state.WorkloadBoundaryDocument != "" {
		t.Errorf("WorkloadBoundaryDocument = %q, want empty", state.WorkloadBoundaryDocument)
	}

	if len(state.ManagedPathRoles) != 0 {
		t.Errorf("ManagedPathRoles = %v, want none", state.ManagedPathRoles)
	}
}

func TestInspect_NonIAMUserPrincipalSkipsUserLookup(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Principal.Type = "identity-center"

	iamClient := &awsfake.IAM{
		GetUserFunc: func(context.Context, *iam.GetUserInput) (*iam.GetUserOutput, error) {
			t.Fatal("GetUser should not be called when principal.type isn't iam-user")

			return nil, nil
		},
		GetRoleFunc: func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return nil, notFound()
		},
		GetPolicyFunc: func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			return nil, notFound()
		},
		ListRolesFunc: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{}, nil
		},
	}
	stsClient := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: ptr("123456789012"), Arn: ptr("arn:...")}, nil
		},
	}

	if _, err := inspect.Inspect(context.Background(), cfg, iamClient, stsClient); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestInspect_AttachedPolicyNotMatchingARNIsIgnored(t *testing.T) {
	t.Parallel()

	const wrongARN = "arn:aws:iam::123456789012:policy/some-other-policy"

	var fetchedARNs []string

	iamClient := &awsfake.IAM{
		GetUserFunc: func(context.Context, *iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, notFound()
		},
		GetRoleFunc: func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{
				Arn: ptr("arn:aws:iam::123456789012:role/terraform-deploy/TerraformDeployRole"), RoleName: ptr("TerraformDeployRole"),
				Path: ptr("/terraform-deploy/"), AssumeRolePolicyDocument: ptr(""),
			}}, nil
		},
		ListAttachedRolePoliciesFunc: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{
				{PolicyArn: ptr(wrongARN), PolicyName: ptr("SomeOtherPolicy")},
			}}, nil
		},
		GetPolicyFunc: func(_ context.Context, params *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			fetchedARNs = append(fetchedARNs, *params.PolicyArn)

			return nil, notFound()
		},
		ListRolesFunc: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{}, nil
		},
	}
	stsClient := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: ptr("123456789012"), Arn: ptr("arn:...")}, nil
		},
	}

	state, err := inspect.Inspect(context.Background(), testConfig(), iamClient, stsClient)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}

	if state.DeployPolicyDocument != "" {
		t.Errorf("DeployPolicyDocument = %q, want empty since the attached policy's ARN doesn't match config", state.DeployPolicyDocument)
	}

	for _, arn := range fetchedARNs {
		if arn == wrongARN {
			t.Errorf("GetPolicy was called with %q, the attached-but-unrelated policy — it should only ever be called with ARNs config actually expects", wrongARN)
		}
	}
}

func TestInspect_CallerIdentityErrorPropagates(t *testing.T) {
	t.Parallel()

	stsClient := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	_, err := inspect.Inspect(context.Background(), testConfig(), &awsfake.IAM{}, stsClient)
	if err == nil {
		t.Fatal("Inspect() error = nil, want the GetCallerIdentity failure to propagate")
	}
}
