// Package inspect implements spec section 6.5's read-only `inspect`
// checklist: it reads the live AWS state the bootstrap config describes
// (account/caller, source principal, MFA, deploy role, attached
// policies, workload boundary, managed-path roles) into a LiveState
// value, without writing anything. Drift/audit analysis over that
// LiveState (spec section 6.5's "managed-path roles" and "boundary
// drift" checks) is a separate stage, once a LiveState exists to
// analyze.
package inspect

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	rampartaws "github.com/qj0r9j0vc2/rampart/internal/bootstrap/aws"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/config"
)

// sourcePrincipalPolicyName is the Sid render.AssumeRolePolicy uses for
// the source principal's grant — spec's config schema has no dedicated
// name/path for this artifact (unlike deploy/deploy_boundary/
// workload_boundary), so Rampart attaches it as an inline policy on the
// user under this name rather than as a separately-tracked managed
// policy.
const sourcePrincipalPolicyName = "AssumeTerraformDeployRole"

// User is the source principal's live state.
type User struct {
	ARN           string
	MFADeviceARNs []string
}

// Role is a live IAM role's state relevant to the bootstrap.
type Role struct {
	ARN                      string
	Name                     string
	Path                     string
	AssumeRolePolicyDocument string
	PermissionsBoundaryARN   string
}

// LiveState is everything read from AWS. Any field left at its zero
// value means the corresponding resource doesn't exist yet (this is the
// normal, expected state before the first apply) rather than an error —
// Inspect only returns an error for something it couldn't determine at
// all, like a failed API call.
type LiveState struct {
	Account   string
	CallerARN string

	SourcePrincipal *User
	DeployRole      *Role

	DeployPolicyDocument          string
	DeployBoundaryDocument        string
	WorkloadBoundaryDocument      string
	SourcePrincipalPolicyDocument string

	ManagedPathRoles []Role
}

// Inspect performs every read spec section 6.5 lists and returns the
// resulting LiveState. It never writes to AWS.
func Inspect(ctx context.Context, cfg *config.Config, iamClient rampartaws.IAMReader, stsClient rampartaws.STSReader) (LiveState, error) {
	var state LiveState

	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return LiveState{}, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}

	state.Account = awssdk.ToString(identity.Account)
	state.CallerARN = awssdk.ToString(identity.Arn)

	if cfg.Principal.Type == "iam-user" {
		user, err := inspectSourcePrincipal(ctx, iamClient, cfg.Principal.Name)
		if err != nil {
			return LiveState{}, err
		}

		state.SourcePrincipal = user

		if user != nil {
			doc, err := inspectInlineUserPolicy(ctx, iamClient, cfg.Principal.Name, sourcePrincipalPolicyName)
			if err != nil {
				return LiveState{}, err
			}

			state.SourcePrincipalPolicyDocument = doc
		}
	}

	deployRole, err := inspectRole(ctx, iamClient, cfg.DeployRole.Name)
	if err != nil {
		return LiveState{}, err
	}

	state.DeployRole = deployRole

	if deployRole != nil {
		deployPolicyARN := policyARN(cfg, cfg.Policies.Deploy.Path, cfg.Policies.Deploy.Name)

		doc, err := inspectAttachedPolicyDocument(ctx, iamClient, deployRole.Name, deployPolicyARN)
		if err != nil {
			return LiveState{}, err
		}

		state.DeployPolicyDocument = doc

		if deployRole.PermissionsBoundaryARN != "" {
			doc, err := fetchPolicyDocument(ctx, iamClient, deployRole.PermissionsBoundaryARN)
			if err != nil {
				return LiveState{}, err
			}

			state.DeployBoundaryDocument = doc
		}
	}

	workloadBoundaryARN := policyARN(cfg, cfg.Policies.WorkloadBoundary.Path, cfg.Policies.WorkloadBoundary.Name)

	doc, err := fetchPolicyDocument(ctx, iamClient, workloadBoundaryARN)
	if err != nil {
		return LiveState{}, err
	}

	state.WorkloadBoundaryDocument = doc

	managedRoles, err := inspectManagedPathRoles(ctx, iamClient, cfg.ManagedRoles.Path)
	if err != nil {
		return LiveState{}, err
	}

	state.ManagedPathRoles = managedRoles

	return state, nil
}

func inspectSourcePrincipal(ctx context.Context, iamClient rampartaws.IAMReader, userName string) (*User, error) {
	out, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
	if isNoSuchEntity(err) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("iam:GetUser %s: %w", userName, err)
	}

	mfaOut, err := iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &userName})
	if err != nil {
		return nil, fmt.Errorf("iam:ListMFADevices %s: %w", userName, err)
	}

	serials := make([]string, 0, len(mfaOut.MFADevices))
	for _, d := range mfaOut.MFADevices {
		serials = append(serials, awssdk.ToString(d.SerialNumber))
	}

	return &User{ARN: awssdk.ToString(out.User.Arn), MFADeviceARNs: serials}, nil
}

func inspectRole(ctx context.Context, iamClient rampartaws.IAMReader, roleName string) (*Role, error) {
	out, err := iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if isNoSuchEntity(err) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("iam:GetRole %s: %w", roleName, err)
	}

	trustPolicy, err := url.QueryUnescape(awssdk.ToString(out.Role.AssumeRolePolicyDocument))
	if err != nil {
		return nil, fmt.Errorf("decoding trust policy for role %s: %w", roleName, err)
	}

	role := &Role{
		ARN:                      awssdk.ToString(out.Role.Arn),
		Name:                     awssdk.ToString(out.Role.RoleName),
		Path:                     awssdk.ToString(out.Role.Path),
		AssumeRolePolicyDocument: trustPolicy,
	}

	if out.Role.PermissionsBoundary != nil {
		role.PermissionsBoundaryARN = awssdk.ToString(out.Role.PermissionsBoundary.PermissionsBoundaryArn)
	}

	return role, nil
}

// inspectAttachedPolicyDocument finds a managed policy attached to
// roleName whose ARN is wantARN and returns its document, or "" if it
// isn't attached — that absence is itself a meaningful drift signal for
// the audit stage, not an error.
func inspectAttachedPolicyDocument(ctx context.Context, iamClient rampartaws.IAMReader, roleName, wantARN string) (string, error) {
	out, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		return "", fmt.Errorf("iam:ListAttachedRolePolicies %s: %w", roleName, err)
	}

	for _, p := range out.AttachedPolicies {
		if awssdk.ToString(p.PolicyArn) == wantARN {
			return fetchPolicyDocument(ctx, iamClient, wantARN)
		}
	}

	return "", nil
}

func inspectInlineUserPolicy(ctx context.Context, iamClient rampartaws.IAMReader, userName, policyName string) (string, error) {
	out, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &userName})
	if err != nil {
		return "", fmt.Errorf("iam:ListUserPolicies %s: %w", userName, err)
	}

	found := false

	for _, name := range out.PolicyNames {
		if name == policyName {
			found = true

			break
		}
	}

	if !found {
		return "", nil
	}

	policyOut, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &userName, PolicyName: &policyName})
	if isNoSuchEntity(err) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("iam:GetUserPolicy %s/%s: %w", userName, policyName, err)
	}

	doc, err := url.QueryUnescape(awssdk.ToString(policyOut.PolicyDocument))
	if err != nil {
		return "", fmt.Errorf("decoding inline policy %s/%s: %w", userName, policyName, err)
	}

	return doc, nil
}

func inspectManagedPathRoles(ctx context.Context, iamClient rampartaws.IAMReader, pathPrefix string) ([]Role, error) {
	paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{PathPrefix: &pathPrefix})

	var roles []Role

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListRoles path %s: %w", pathPrefix, err)
		}

		for _, r := range page.Roles {
			role := Role{
				ARN:  awssdk.ToString(r.Arn),
				Name: awssdk.ToString(r.RoleName),
				Path: awssdk.ToString(r.Path),
			}

			if r.PermissionsBoundary != nil {
				role.PermissionsBoundaryARN = awssdk.ToString(r.PermissionsBoundary.PermissionsBoundaryArn)
			}

			roles = append(roles, role)
		}
	}

	return roles, nil
}

// fetchPolicyDocument reads a managed policy's current default version
// and returns its (URL-decoded) document, or "" if the policy doesn't
// exist yet.
func fetchPolicyDocument(ctx context.Context, iamClient rampartaws.IAMReader, policyARN string) (string, error) {
	policyOut, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyARN})
	if isNoSuchEntity(err) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("iam:GetPolicy %s: %w", policyARN, err)
	}

	versionOut, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyARN,
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return "", fmt.Errorf("iam:GetPolicyVersion %s: %w", policyARN, err)
	}

	doc, err := url.QueryUnescape(awssdk.ToString(versionOut.PolicyVersion.Document))
	if err != nil {
		return "", fmt.Errorf("decoding policy document %s: %w", policyARN, err)
	}

	return doc, nil
}

func isNoSuchEntity(err error) bool {
	var nse *types.NoSuchEntityException

	return errors.As(err, &nse)
}

func policyARN(cfg *config.Config, path, name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:policy%s%s", cfg.AWS.Partition, cfg.AWS.AccountID, path, name)
}
