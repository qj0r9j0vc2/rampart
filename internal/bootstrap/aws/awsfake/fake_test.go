package awsfake_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/aws/awsfake"
)

// TestIAM_RoutesEachMethod proves each IAM interface method routes to
// its own configured func rather than, say, two methods accidentally
// sharing a field from a copy-paste mistake.
func TestIAM_RoutesEachMethod(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("sentinel")
	ctx := context.Background()

	fake := &awsfake.IAM{
		GetUserFunc: func(context.Context, *iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, wantErr
		},
		ListMFADevicesFunc: func(context.Context, *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{}, nil
		},
		GetRoleFunc: func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{}, nil
		},
		ListAttachedRolePoliciesFunc: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		},
		GetPolicyFunc: func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{}, nil
		},
		GetPolicyVersionFunc: func(context.Context, *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{}, nil
		},
		ListRolesFunc: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{}, nil
		},
		ListUserPoliciesFunc: func(context.Context, *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
			return &iam.ListUserPoliciesOutput{}, nil
		},
		GetUserPolicyFunc: func(context.Context, *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
			return &iam.GetUserPolicyOutput{}, nil
		},
	}

	if _, err := fake.GetUser(ctx, &iam.GetUserInput{}); !errors.Is(err, wantErr) {
		t.Errorf("GetUser() error = %v, want %v", err, wantErr)
	}

	if out, err := fake.ListMFADevices(ctx, &iam.ListMFADevicesInput{}); err != nil || out == nil {
		t.Errorf("ListMFADevices() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.GetRole(ctx, &iam.GetRoleInput{}); err != nil || out == nil {
		t.Errorf("GetRole() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{}); err != nil || out == nil {
		t.Errorf("ListAttachedRolePolicies() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.GetPolicy(ctx, &iam.GetPolicyInput{}); err != nil || out == nil {
		t.Errorf("GetPolicy() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{}); err != nil || out == nil {
		t.Errorf("GetPolicyVersion() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.ListRoles(ctx, &iam.ListRolesInput{}); err != nil || out == nil {
		t.Errorf("ListRoles() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{}); err != nil || out == nil {
		t.Errorf("ListUserPolicies() = %v, %v, want a non-nil output and nil error", out, err)
	}

	if out, err := fake.GetUserPolicy(ctx, &iam.GetUserPolicyInput{}); err != nil || out == nil {
		t.Errorf("GetUserPolicy() = %v, %v, want a non-nil output and nil error", out, err)
	}
}

func TestSTS_GetCallerIdentity(t *testing.T) {
	t.Parallel()

	fake := &awsfake.STS{
		GetCallerIdentityFunc: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			account := "123456789012"

			return &sts.GetCallerIdentityOutput{Account: &account}, nil
		},
	}

	out, err := fake.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("GetCallerIdentity() error = %v", err)
	}

	if out.Account == nil || *out.Account != "123456789012" {
		t.Errorf("GetCallerIdentity().Account = %v, want 123456789012", out.Account)
	}
}
