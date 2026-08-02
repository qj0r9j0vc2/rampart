package diff

import (
	"fmt"
	"strconv"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

// DiffTrustPolicy compares two versions of trust-policy.json (spec
// section 18: "Trust-principal changes", "MFA requirement changes").
// Rampart only ever generates a single-statement trust policy, so this
// compares the first statement of each rather than matching by Sid.
func DiffTrustPolicy(oldDoc, newDoc render.TrustDocument) Result {
	var oldStmt, newStmt render.TrustStatement

	if len(oldDoc.Statement) > 0 {
		oldStmt = oldDoc.Statement[0]
	}

	if len(newDoc.Statement) > 0 {
		newStmt = newDoc.Statement[0]
	}

	var changes []Change

	changes = append(changes, diffPrincipal(oldStmt, newStmt)...)
	changes = append(changes, diffMFA(oldStmt, newStmt)...)

	sortChanges(changes)

	return Result{Name: "trust-policy.json", Changes: changes}
}

// diffPrincipal flags any change to who may assume the role as a
// security-invariant violation regardless of direction — narrowing to a
// different principal is still "the wrong principal can now assume this"
// until reviewed, not a change diff can safely wave through either way.
func diffPrincipal(oldStmt, newStmt render.TrustStatement) []Change {
	oldPrincipal := oldStmt.Principal["AWS"]
	newPrincipal := newStmt.Principal["AWS"]

	if oldPrincipal == newPrincipal {
		return nil
	}

	return []Change{{
		Statement:   "AssumeWithMFA",
		Kind:        SecurityInvariantViolation,
		Description: fmt.Sprintf("~ trust principal changed: %s -> %s", describeOrNone(oldPrincipal), describeOrNone(newPrincipal)),
	}}
}

// diffMFA flags MFA requirement changes. Losing the MFA condition
// entirely is a security-invariant violation (spec section 4.2: the
// deploy role must not be assumable without MFA when configured as
// required — this is exactly what RMP-E008 blocks on generation, so a
// diff introducing it needs the same severity, not just "weakening").
// A looser (larger) MultiFactorAuthAge window is a weakening; a
// tighter one is a tightening.
func diffMFA(oldStmt, newStmt render.TrustStatement) []Change {
	oldRequiresMFA := oldStmt.Condition != nil && oldStmt.Condition.Bool["aws:MultiFactorAuthPresent"] == "true"
	newRequiresMFA := newStmt.Condition != nil && newStmt.Condition.Bool["aws:MultiFactorAuthPresent"] == "true"

	if oldRequiresMFA && !newRequiresMFA {
		return []Change{{
			Statement:   "AssumeWithMFA",
			Kind:        SecurityInvariantViolation,
			Description: "- MFA requirement removed",
		}}
	}

	var changes []Change

	if !oldRequiresMFA && newRequiresMFA {
		changes = append(changes, Change{Statement: "AssumeWithMFA", Kind: ConditionTightening, Description: "+ MFA requirement added"})
	}

	oldAge := mfaMaxAge(oldStmt)
	newAge := mfaMaxAge(newStmt)

	if oldRequiresMFA && newRequiresMFA && oldAge != newAge {
		kind := ConditionTightening
		if numericGreater(newAge, oldAge) {
			kind = ConditionWeakening
		}

		changes = append(changes, Change{
			Statement:   "AssumeWithMFA",
			Kind:        kind,
			Description: fmt.Sprintf("~ aws:MultiFactorAuthAge changed: %s -> %s", oldAge, newAge),
		})
	}

	return changes
}

// numericGreater reports whether a > b, comparing numerically when both
// parse as integers (aws:MultiFactorAuthAge should always be one) and
// falling back to a string comparison otherwise rather than erroring —
// this is a diff description, not something that should ever fail to
// produce output over a malformed value.
func numericGreater(a, b string) bool {
	aNum, aErr := strconv.Atoi(a)
	bNum, bErr := strconv.Atoi(b)

	if aErr == nil && bErr == nil {
		return aNum > bNum
	}

	return a > b
}

func mfaMaxAge(s render.TrustStatement) string {
	if s.Condition == nil {
		return ""
	}

	return s.Condition.NumericLessThanEquals["aws:MultiFactorAuthAge"]
}

func describeOrNone(s string) string {
	if s == "" {
		return "(none)"
	}

	return s
}
