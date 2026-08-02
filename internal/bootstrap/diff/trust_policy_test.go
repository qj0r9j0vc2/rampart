package diff_test

import (
	"testing"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/diff"
	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

func mfaTrustDoc(principal string, requireMFA bool, maxAge string) render.TrustDocument {
	s := render.TrustStatement{
		Sid:       "AssumeWithMFA",
		Effect:    "Allow",
		Principal: map[string]string{"AWS": principal},
		Action:    "sts:AssumeRole",
	}

	if requireMFA {
		s.Condition = &render.TrustCondition{Bool: map[string]string{"aws:MultiFactorAuthPresent": "true"}}
		if maxAge != "" {
			s.Condition.NumericLessThanEquals = map[string]string{"aws:MultiFactorAuthAge": maxAge}
		}
	}

	return render.TrustDocument{Statement: []render.TrustStatement{s}}
}

func TestDiffTrustPolicy_MFARemoved(t *testing.T) {
	t.Parallel()

	oldDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", true, "3600")
	newDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", false, "")

	result := diff.DiffTrustPolicy(oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "MFA requirement removed"); kind != diff.SecurityInvariantViolation {
		t.Errorf("Kind = %q, want %q (removing MFA must be at least as severe as an expansion)", kind, diff.SecurityInvariantViolation)
	}

	if !result.RequiresApproval() {
		t.Error("RequiresApproval() = false, want true")
	}
}

func TestDiffTrustPolicy_MFAAdded(t *testing.T) {
	t.Parallel()

	oldDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", false, "")
	newDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", true, "3600")

	result := diff.DiffTrustPolicy(oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "MFA requirement added"); kind != diff.ConditionTightening {
		t.Errorf("Kind = %q, want %q", kind, diff.ConditionTightening)
	}
}

func TestDiffTrustPolicy_MaxAgeDirectionality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		oldAge    string
		newAge    string
		wantWiden diff.ChangeKind
	}{
		{"widened window is a weakening", "3600", "7200", diff.ConditionWeakening},
		{"narrowed window is a tightening", "7200", "3600", diff.ConditionTightening},
		// Regression case: naive string comparison ("9" > "10" lexically)
		// would get this backwards — 9 < 10 numerically, so this must
		// classify as a widening (weakening), not a narrowing.
		{"single-to-double-digit widening classifies numerically, not lexically", "9", "10", diff.ConditionWeakening},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", true, tt.oldAge)
			newDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", true, tt.newAge)

			result := diff.DiffTrustPolicy(oldDoc, newDoc)
			if kind := findKind(t, result.Changes, "aws:MultiFactorAuthAge changed"); kind != tt.wantWiden {
				t.Errorf("Kind = %q, want %q", kind, tt.wantWiden)
			}
		})
	}
}

func TestDiffTrustPolicy_PrincipalChanged(t *testing.T) {
	t.Parallel()

	oldDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/alice", true, "3600")
	newDoc := mfaTrustDoc("arn:aws:iam::123456789012:user/bob", true, "3600")

	result := diff.DiffTrustPolicy(oldDoc, newDoc)

	if kind := findKind(t, result.Changes, "trust principal changed"); kind != diff.SecurityInvariantViolation {
		t.Errorf("Kind = %q, want %q", kind, diff.SecurityInvariantViolation)
	}
}

func TestDiffTrustPolicy_NoChange(t *testing.T) {
	t.Parallel()

	doc := mfaTrustDoc("arn:aws:iam::123456789012:user/cli-user", true, "3600")

	result := diff.DiffTrustPolicy(doc, doc)

	if len(result.Changes) != 0 {
		t.Errorf("Changes = %+v, want none", result.Changes)
	}

	if result.RequiresApproval() {
		t.Error("RequiresApproval() = true, want false")
	}
}
