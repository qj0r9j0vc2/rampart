// Package awsfake provides function-field test doubles for
// aws.IAMReader and aws.STSReader (like net/http/httptest.HandlerFunc:
// each field is nil-able, and a nil field panics loudly if a test calls
// an operation it never expected to). It's a separate package from
// internal/bootstrap/aws so the real package's surface stays exactly
// the interfaces and constructor real callers need, while every other
// package in the M3 stack can still import a shared fake for its own
// tests instead of each hand-rolling one.
package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	rampartaws "github.com/qj0r9j0vc2/rampart/internal/bootstrap/aws"
)

var (
	_ rampartaws.IAMReader = (*IAM)(nil)
	_ rampartaws.STSReader = (*STS)(nil)
)

// IAM is a test double for aws.IAMReader. Set only the func fields a
// given test actually exercises; calling an unset one panics with a
// clear message rather than a nil-pointer dereference.
type IAM struct {
	GetUserFunc                  func(ctx context.Context, params *iam.GetUserInput) (*iam.GetUserOutput, error)
	ListMFADevicesFunc           func(ctx context.Context, params *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error)
	GetRoleFunc                  func(ctx context.Context, params *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	ListAttachedRolePoliciesFunc func(ctx context.Context, params *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicyFunc                func(ctx context.Context, params *iam.GetPolicyInput) (*iam.GetPolicyOutput, error)
	GetPolicyVersionFunc         func(ctx context.Context, params *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error)
	ListRolesFunc                func(ctx context.Context, params *iam.ListRolesInput) (*iam.ListRolesOutput, error)
	ListUserPoliciesFunc         func(ctx context.Context, params *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicyFunc            func(ctx context.Context, params *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error)
}

func (f *IAM) GetUser(ctx context.Context, params *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return f.GetUserFunc(ctx, params)
}

func (f *IAM) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, _ ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return f.ListMFADevicesFunc(ctx, params)
}

func (f *IAM) GetRole(ctx context.Context, params *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return f.GetRoleFunc(ctx, params)
}

func (f *IAM) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return f.ListAttachedRolePoliciesFunc(ctx, params)
}

func (f *IAM) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return f.GetPolicyFunc(ctx, params)
}

func (f *IAM) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return f.GetPolicyVersionFunc(ctx, params)
}

func (f *IAM) ListRoles(ctx context.Context, params *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return f.ListRolesFunc(ctx, params)
}

func (f *IAM) ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return f.ListUserPoliciesFunc(ctx, params)
}

func (f *IAM) GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	return f.GetUserPolicyFunc(ctx, params)
}

// STS is a test double for aws.STSReader.
type STS struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (f *STS) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.GetCallerIdentityFunc(ctx, params)
}
