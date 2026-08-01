package diff_test

import (
	"strings"
	"testing"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/diff"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

func findKind(t *testing.T, changes []diff.Change, substr string) diff.ChangeKind {
	t.Helper()

	for _, c := range changes {
		if strings.Contains(c.Description, substr) {
			return c.Kind
		}
	}

	t.Fatalf("no change found containing %q in %+v", substr, changes)

	return ""
}

// TestDiffDocument_SpecExample reproduces spec section 18's own example
// almost exactly: a new allowed action, a widened PassRole service
// allowlist, and a removed explicit deny — and confirms the overall
// result is SECURITY-SENSITIVE EXPANSION requiring
// --allow-boundary-expansion, exactly like the spec shows.
func TestDiffDocument_SpecExample(t *testing.T) {
	t.Parallel()

	oldDoc := render.Document{Statements: []render.Statement{
		{
			Sid: "PassManagedRolesToApprovedServices", Effect: "Allow", Action: []string{"iam:PassRole"},
			Resource: []string{"arn:aws:iam::123456789012:role/terraform-managed/*"},
			Condition: &render.Condition{StringEquals: map[string]any{
				"iam:PassedToService": []string{"ecs-tasks.amazonaws.com"},
			}},
		},
		{
			Sid: "DenyBoundaryPolicyMutation", Effect: "Deny",
			Action:   []string{"iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"},
			Resource: []string{"arn:aws:iam::123456789012:policy/boundaries/*"},
		},
		{Sid: "NonIAM0", Effect: "Allow", Action: []string{"ecs:DescribeServices"}, Resource: []string{"*"}},
	}}

	newDoc := render.Document{Statements: []render.Statement{
		{
			Sid: "PassManagedRolesToApprovedServices", Effect: "Allow", Action: []string{"iam:PassRole"},
			Resource: []string{"arn:aws:iam::123456789012:role/terraform-managed/*"},
			Condition: &render.Condition{StringEquals: map[string]any{
				"iam:PassedToService": []string{"ecs-tasks.amazonaws.com", "events.amazonaws.com"},
			}},
		},
		{
			Sid: "DenyBoundaryPolicyMutation", Effect: "Deny",
			Action:   []string{"iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"},
			Resource: []string{"arn:aws:iam::123456789012:policy/boundaries/*"},
		},
		{Sid: "NonIAM0", Effect: "Allow", Action: []string{"ecs:DescribeServices", "ecs:UpdateService"}, Resource: []string{"*"}},
	}}

	result := diff.DiffDocument("TerraformDeployBoundary", oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "+ Allow ecs:UpdateService"); kind != diff.PermissionExpansion {
		t.Errorf("new allowed action classified %q, want %q", kind, diff.PermissionExpansion)
	}

	if kind := findKind(t, result.Changes, "+ events.amazonaws.com"); kind != diff.ConditionWeakening {
		t.Errorf("widened service allowlist classified %q, want %q", kind, diff.ConditionWeakening)
	}

	if kind := findKind(t, result.Changes, "- Deny iam:CreatePolicyVersion"); kind != diff.PermissionExpansion {
		t.Errorf("removed explicit deny classified %q, want %q", kind, diff.PermissionExpansion)
	}

	if got := result.Classification(); got != diff.PermissionExpansion && !got.IsExpansion() {
		t.Errorf("Classification() = %q, want an expansion-class kind", got)
	}

	if !result.RequiresApproval() {
		t.Error("RequiresApproval() = false, want true — this diff must require --allow-boundary-expansion")
	}

	rendered := result.String()
	if !strings.Contains(rendered, "SECURITY-SENSITIVE EXPANSION") {
		t.Errorf("String() = %q, want it to contain \"SECURITY-SENSITIVE EXPANSION\"", rendered)
	}

	if !strings.Contains(rendered, "Apply requires --allow-boundary-expansion") {
		t.Errorf("String() = %q, want the approval-required line", rendered)
	}
}

func TestDiffDocument_NoChange(t *testing.T) {
	t.Parallel()

	doc := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
	}}

	result := diff.DiffDocument("deploy-boundary.json", doc, doc)

	if len(result.Changes) != 0 {
		t.Errorf("Changes = %+v, want none for identical documents", result.Changes)
	}

	if got := result.Classification(); got != diff.NoChange {
		t.Errorf("Classification() = %q, want %q", got, diff.NoChange)
	}

	if result.RequiresApproval() {
		t.Error("RequiresApproval() = true, want false for an unchanged document")
	}
}

func TestDiffDocument_PermissionReduction(t *testing.T) {
	t.Parallel()

	oldDoc := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole", "iam:ListRolePolicies"}, Resource: []string{"*"}},
	}}
	newDoc := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
	}}

	result := diff.DiffDocument("deploy-boundary.json", oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "- Allow iam:ListRolePolicies"); kind != diff.PermissionReduction {
		t.Errorf("removed allowed action classified %q, want %q", kind, diff.PermissionReduction)
	}

	if result.RequiresApproval() {
		t.Error("RequiresApproval() = true, want false — a pure reduction needs no approval")
	}
}

func TestDiffDocument_WholeStatementAddedAndRemoved(t *testing.T) {
	t.Parallel()

	oldDoc := render.Document{Statements: []render.Statement{
		{Sid: "DenyOrganizationManagement", Effect: "Deny", Action: []string{"organizations:*"}, Resource: []string{"*"}},
	}}
	newDoc := render.Document{Statements: []render.Statement{
		{Sid: "IAMRead", Effect: "Allow", Action: []string{"iam:GetRole"}, Resource: []string{"*"}},
	}}

	result := diff.DiffDocument("deploy-boundary.json", oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "+ Allow iam:GetRole"); kind != diff.PermissionExpansion {
		t.Errorf("new statement's allow action classified %q, want %q", kind, diff.PermissionExpansion)
	}

	if kind := findKind(t, result.Changes, "- Deny organizations:*"); kind != diff.PermissionExpansion {
		t.Errorf("removing an entire Deny statement's action classified %q, want %q (removing a deny is always an expansion)", kind, diff.PermissionExpansion)
	}
}

func TestDiffDocument_ResourceBroadeningAndNarrowing(t *testing.T) {
	t.Parallel()

	oldDoc := render.Document{Statements: []render.Statement{
		{Sid: "CreateRoleWithRequiredBoundary", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"arn:aws:iam::123456789012:role/terraform-managed/*"}},
	}}
	broadened := render.Document{Statements: []render.Statement{
		{Sid: "CreateRoleWithRequiredBoundary", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"*"}},
	}}

	result := diff.DiffDocument("deploy-boundary.json", oldDoc, broadened)
	if kind := findKind(t, result.Changes, "Resource broadened to *"); kind != diff.ResourceBroadening {
		t.Errorf("wildcard resource classified %q, want %q", kind, diff.ResourceBroadening)
	}

	narrowed := render.Document{Statements: []render.Statement{
		{Sid: "CreateRoleWithRequiredBoundary", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{}},
	}}
	result = diff.DiffDocument("deploy-boundary.json", oldDoc, narrowed)

	if kind := findKind(t, result.Changes, "Resource narrowed"); kind != diff.ResourceNarrowing {
		t.Errorf("removed resource classified %q, want %q", kind, diff.ResourceNarrowing)
	}
}

func TestDiffDocument_ConditionAddedAndRemoved(t *testing.T) {
	t.Parallel()

	withoutCondition := render.Document{Statements: []render.Statement{
		{Sid: "CreateRoleWithRequiredBoundary", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"*"}},
	}}
	withCondition := render.Document{Statements: []render.Statement{
		{
			Sid: "CreateRoleWithRequiredBoundary", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"*"},
			Condition: &render.Condition{StringEquals: map[string]any{"iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/boundaries/TerraformWorkloadBoundary"}},
		},
	}}

	added := diff.DiffDocument("deploy-boundary.json", withoutCondition, withCondition)
	if kind := findKind(t, added.Changes, "condition added"); kind != diff.ConditionTightening {
		t.Errorf("added condition classified %q, want %q", kind, diff.ConditionTightening)
	}

	removed := diff.DiffDocument("deploy-boundary.json", withCondition, withoutCondition)
	if kind := findKind(t, removed.Changes, "condition removed"); kind != diff.ConditionWeakening {
		t.Errorf("removed condition classified %q, want %q (spec exit criteria: condition weakening classifies as expansion)", kind, diff.ConditionWeakening)
	}

	if !removed.RequiresApproval() {
		t.Error("RequiresApproval() = false, want true — removing a condition must require --allow-boundary-expansion")
	}
}

func TestDiffDocument_ScalarConditionValueWildcardHeuristic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		oldVal string
		newVal string
		want   diff.ChangeKind
	}{
		{"wildcard replaced by exact value narrows", "arn:aws:iam::123456789012:policy/boundaries/*", "arn:aws:iam::123456789012:policy/boundaries/TerraformWorkloadBoundary", diff.ConditionTightening},
		{"exact value replaced by wildcard widens", "arn:aws:iam::123456789012:policy/boundaries/TerraformWorkloadBoundary", "arn:aws:iam::123456789012:policy/boundaries/*", diff.ConditionWeakening},
		{"two different exact values default to needing review", "arn:aws:iam::123456789012:policy/boundaries/A", "arn:aws:iam::123456789012:policy/boundaries/B", diff.ConditionWeakening},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := render.Document{Statements: []render.Statement{
				{Sid: "S", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"*"}, Condition: &render.Condition{StringEquals: map[string]any{"iam:PermissionsBoundary": tt.oldVal}}},
			}}
			newDoc := render.Document{Statements: []render.Statement{
				{Sid: "S", Effect: "Allow", Action: []string{"iam:CreateRole"}, Resource: []string{"*"}, Condition: &render.Condition{StringEquals: map[string]any{"iam:PermissionsBoundary": tt.newVal}}},
			}}

			result := diff.DiffDocument("deploy-boundary.json", oldDoc, newDoc)
			if kind := findKind(t, result.Changes, "iam:PermissionsBoundary changed"); kind != tt.want {
				t.Errorf("Kind = %q, want %q", kind, tt.want)
			}
		})
	}
}

func TestDiffDocument_JSONUnmarshaledConditionValues(t *testing.T) {
	t.Parallel()

	// Simulates loading two rampart.yaml-generated JSON files from disk
	// (`rampart bootstrap diff` on files, not in-memory Documents): list
	// values decode as []any, not []string.
	oldDoc := render.Document{Statements: []render.Statement{
		{Sid: "S", Effect: "Allow", Action: []string{"iam:PassRole"}, Resource: []string{"*"}, Condition: &render.Condition{StringEquals: map[string]any{
			"iam:PassedToService": []any{"ecs-tasks.amazonaws.com"},
		}}},
	}}
	newDoc := render.Document{Statements: []render.Statement{
		{Sid: "S", Effect: "Allow", Action: []string{"iam:PassRole"}, Resource: []string{"*"}, Condition: &render.Condition{StringEquals: map[string]any{
			"iam:PassedToService": []any{"ecs-tasks.amazonaws.com", "events.amazonaws.com"},
		}}},
	}}

	result := diff.DiffDocument("deploy-boundary.json", oldDoc, newDoc)
	if kind := findKind(t, result.Changes, "+ events.amazonaws.com"); kind != diff.ConditionWeakening {
		t.Errorf("Kind = %q, want %q", kind, diff.ConditionWeakening)
	}
}
