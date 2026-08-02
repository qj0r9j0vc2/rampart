// Package aws is the read-only AWS boundary for M3 ("Inspect and plan",
// spec section 22): a narrow interface over exactly the IAM/STS
// operations spec section 6.5's inspect checklist needs, plus a shared
// constructor for the concrete SDK clients.
//
// Existing AWS-touching code elsewhere in this repo (src/watch.go,
// src/compare.go, src/credentials.go) calls the SDK's concrete *iam.Client
// and *sts.Client types directly, with config.LoadDefaultConfig +
// NewFromConfig copy-pasted at each call site and no abstraction for
// tests — those are gated behind a `-tags auth` build tag and only run
// against a real AWS account. Section 20.1's AWSInspector/AWSApplier
// interfaces call for something testable without live credentials, so
// this package defines interfaces instead: IAMReader and STSReader are
// satisfied structurally by *iam.Client/*sts.Client (no wrapper needed
// in production), and a hand-written fake satisfies them in tests.
package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// defaultTimeout bounds every read-only call this package makes so a
// hung network call can't block `inspect`/`plan` indefinitely.
const defaultTimeout = 30 * time.Second

// IAMReader is exactly the IAM operations spec section 6.5's inspect
// checklist needs. *iam.Client implements this already; nothing else
// does or should.
type IAMReader interface {
	GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
}

// STSReader is exactly the STS operation the inspect checklist needs.
type STSReader interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// AWSConfigError wraps a failure loading the ambient AWS configuration
// (shared config/credentials files, environment variables, instance
// role, ...).
type AWSConfigError struct {
	Err error
}

func (e *AWSConfigError) Error() string {
	return fmt.Sprintf("loading AWS config: %v", e.Err)
}

func (e *AWSConfigError) Unwrap() error {
	return e.Err
}

// NewClients loads the ambient AWS configuration (the same shared
// config/credentials resolution `aws sts get-caller-identity` and every
// other AWS CLI/SDK call uses) and returns ready-to-use IAM and STS
// clients. There is deliberately no profile/region override parameter:
// spec's `inspect`/`plan` commands are documented as running under
// whatever AWS_PROFILE the operator has already set
// (AWS_PROFILE=bootstrap-readonly rampart bootstrap inspect, section 6.5),
// not as a flag this package should re-implement.
func NewClients(ctx context.Context) (*iam.Client, *sts.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, nil, &AWSConfigError{Err: err}
	}

	return iam.NewFromConfig(cfg), sts.NewFromConfig(cfg), nil
}
