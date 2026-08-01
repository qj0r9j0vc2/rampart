// Package diff implements the semantic diff engine (spec section 18): it
// compares two versions of a rendered artifact statement-by-statement
// (not as formatted JSON text) and classifies each difference per the
// spec section 6.4 / 16.4 categories, so `rampart bootstrap diff` and the
// apply stage's boundary-expansion gate can tell a harmless reduction
// apart from a change that needs --allow-boundary-expansion.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qj0r9j0vc2/rampart/internal/bootstrap/render"
)

// ChangeKind is one of the classifications spec section 6.4 lists for
// `rampart bootstrap diff` output.
type ChangeKind string

const (
	NoChange                   ChangeKind = "no-semantic-change"
	PermissionReduction        ChangeKind = "permission-reduction"
	PermissionExpansion        ChangeKind = "permission-expansion"
	ConditionTightening        ChangeKind = "condition-tightening"
	ConditionWeakening         ChangeKind = "condition-weakening"
	ResourceNarrowing          ChangeKind = "resource-narrowing"
	ResourceBroadening         ChangeKind = "resource-broadening"
	SecurityInvariantViolation ChangeKind = "security-invariant-violation"
)

// IsExpansion reports whether a change of this kind requires
// --allow-boundary-expansion (spec section 16.4): it adds an allowed
// action, broadens a resource, removes/weakens a condition, removes an
// explicit deny, widens a service allowlist, or otherwise touches a
// security invariant.
func (k ChangeKind) IsExpansion() bool {
	switch k {
	case PermissionExpansion, ConditionWeakening, ResourceBroadening, SecurityInvariantViolation:
		return true
	default:
		return false
	}
}

// Change is a single detected difference within one statement (or a
// whole statement added/removed).
type Change struct {
	Statement   string // Sid the change belongs to
	Kind        ChangeKind
	Description string // human-readable line, e.g. "+ Allow ecs:UpdateService"
}

// Result is every change detected between two versions of one artifact.
type Result struct {
	Name    string
	Changes []Change
}

// Classification is the overall, worst-case classification across every
// change: if any change requires expansion approval, the whole result
// does (spec section 16.4 — the gate is "does anything in this diff
// need review", not an average).
func (r Result) Classification() ChangeKind {
	if len(r.Changes) == 0 {
		return NoChange
	}

	worst := ChangeKind("")
	for _, c := range r.Changes {
		if c.Kind.IsExpansion() {
			return c.Kind
		}

		worst = c.Kind
	}

	return worst
}

// RequiresApproval reports whether apply needs --allow-boundary-expansion
// (spec section 16.4) before proceeding with this change.
func (r Result) RequiresApproval() bool {
	return r.Classification().IsExpansion()
}

// String renders the diff in the section 18 example's style: an artifact
// name header, one line per change, and a trailing classification.
func (r Result) String() string {
	var b strings.Builder

	b.WriteString(r.Name + "\n\n")

	for _, c := range r.Changes {
		b.WriteString(c.Description + "\n")
	}

	b.WriteString("\nClassification: " + classificationLabel(r.Classification()) + "\n")

	if r.RequiresApproval() {
		b.WriteString("Apply requires --allow-boundary-expansion\n")
	}

	return b.String()
}

func classificationLabel(k ChangeKind) string {
	switch k {
	case NoChange:
		return "NO SEMANTIC CHANGE"
	case PermissionReduction:
		return "PERMISSION REDUCTION"
	case PermissionExpansion, ConditionWeakening, ResourceBroadening, SecurityInvariantViolation:
		return "SECURITY-SENSITIVE EXPANSION"
	case ConditionTightening:
		return "CONDITION TIGHTENING"
	case ResourceNarrowing:
		return "RESOURCE NARROWING"
	default:
		return strings.ToUpper(string(k))
	}
}

// DiffDocument compares two versions of a Resource-based artifact
// (deploy-policy.json, deploy-boundary.json or workload-boundary.json)
// statement by statement, matched by Sid — every statement Rampart
// generates has a stable, meaningful Sid, so Sid is the natural join key
// between an old and new render.
func DiffDocument(name string, oldDoc, newDoc render.Document) Result {
	oldBySid := indexStatements(oldDoc.Statements)
	newBySid := indexStatements(newDoc.Statements)

	var changes []Change

	for sid, newStmt := range newBySid {
		if oldStmt, ok := oldBySid[sid]; ok {
			changes = append(changes, diffStatement(sid, oldStmt, newStmt)...)
		} else {
			changes = append(changes, wholeStatementChange(sid, newStmt, true)...)
		}
	}

	for sid, oldStmt := range oldBySid {
		if _, ok := newBySid[sid]; !ok {
			changes = append(changes, wholeStatementChange(sid, oldStmt, false)...)
		}
	}

	sortChanges(changes)

	return Result{Name: name, Changes: changes}
}

func indexStatements(statements []render.Statement) map[string]render.Statement {
	out := make(map[string]render.Statement, len(statements))
	for _, s := range statements {
		out[s.Sid] = s
	}

	return out
}

// wholeStatementChange handles a statement that's entirely new (added)
// or entirely gone (removed). An Allow statement appearing is an
// expansion and disappearing is a reduction; a Deny statement appearing
// is a reduction (a new restriction) and disappearing is an expansion
// (spec section 16.4: "Removes an explicit deny").
func wholeStatementChange(sid string, s render.Statement, added bool) []Change {
	sign := "-"
	if added {
		sign = "+"
	}

	kind := PermissionExpansion
	if (s.Effect == "Allow") != added {
		kind = PermissionReduction
	}

	var changes []Change

	for _, action := range s.Action {
		changes = append(changes, Change{
			Statement:   sid,
			Kind:        kind,
			Description: fmt.Sprintf("%s %s %s", sign, s.Effect, action),
		})
	}

	return changes
}

func diffStatement(sid string, oldStmt, newStmt render.Statement) []Change {
	var changes []Change

	changes = append(changes, diffActions(sid, oldStmt, newStmt)...)
	changes = append(changes, diffResources(sid, oldStmt, newStmt)...)
	changes = append(changes, diffConditions(sid, oldStmt, newStmt)...)

	return changes
}

// diffActions detects action additions/removals. Adding an action to an
// Allow statement expands; adding one to a Deny statement reduces.
// Removing works the other way — removing an action from a Deny
// statement is exactly spec section 18's "explicit-deny changes"
// example ("- Deny iam:CreatePolicyVersion on /boundaries/*").
func diffActions(sid string, oldStmt, newStmt render.Statement) []Change {
	added, removed := diffStrings(oldStmt.Action, newStmt.Action)

	var changes []Change

	for _, action := range added {
		kind := PermissionExpansion
		if newStmt.Effect == "Deny" {
			kind = PermissionReduction
		}

		changes = append(changes, Change{Statement: sid, Kind: kind, Description: fmt.Sprintf("+ %s %s", newStmt.Effect, action)})
	}

	for _, action := range removed {
		kind := PermissionReduction
		if oldStmt.Effect == "Deny" {
			kind = PermissionExpansion
		}

		changes = append(changes, Change{Statement: sid, Kind: kind, Description: fmt.Sprintf("- %s %s", oldStmt.Effect, action)})
	}

	return changes
}

// diffResources detects resource additions/removals, calling out "*"
// specifically (spec section 18: "* broadening") since a wildcard
// resource is always the most permissive case regardless of what it
// replaces.
func diffResources(sid string, oldStmt, newStmt render.Statement) []Change {
	added, removed := diffStrings(oldStmt.Resource, newStmt.Resource)

	var changes []Change

	for _, r := range added {
		desc := fmt.Sprintf("~ %s Resource broadened: + %s", sid, r)
		if r == "*" {
			desc = fmt.Sprintf("~ %s Resource broadened to *", sid)
		}

		changes = append(changes, Change{Statement: sid, Kind: ResourceBroadening, Description: desc})
	}

	for _, r := range removed {
		changes = append(changes, Change{Statement: sid, Kind: ResourceNarrowing, Description: fmt.Sprintf("~ %s Resource narrowed: - %s", sid, r)})
	}

	return changes
}

// diffConditions detects condition additions/removals and operator/value
// changes (spec section 18). Removing a condition key weakens (section
// 16.4: "removes ... a condition"); adding one tightens. A changed
// list-valued condition (a service allowlist, e.g. iam:PassedToService)
// is diffed element-by-element so widening and narrowing the allowlist
// are told apart, not just flagged as "changed". A changed scalar value
// (e.g. a boundary ARN) is classified by wildcard presence when
// possible, defaulting to weakening — needs-review — when the direction
// can't be determined from the values alone.
func diffConditions(sid string, oldStmt, newStmt render.Statement) []Change {
	oldEq := conditionMap(oldStmt.Condition)
	newEq := conditionMap(newStmt.Condition)

	var changes []Change

	for key, newVal := range newEq {
		oldVal, existed := oldEq[key]
		if !existed {
			changes = append(changes, Change{Statement: sid, Kind: ConditionTightening, Description: fmt.Sprintf("~ %s %s condition added: %s", sid, key, describeValue(newVal))})

			continue
		}

		changes = append(changes, diffConditionValue(sid, key, oldVal, newVal)...)
	}

	for key, oldVal := range oldEq {
		if _, stillPresent := newEq[key]; !stillPresent {
			changes = append(changes, Change{Statement: sid, Kind: ConditionWeakening, Description: fmt.Sprintf("~ %s %s condition removed (was %s)", sid, key, describeValue(oldVal))})
		}
	}

	return changes
}

func diffConditionValue(sid, key string, oldVal, newVal any) []Change {
	oldList, oldIsList := asStringList(oldVal)
	newList, newIsList := asStringList(newVal)

	if oldIsList && newIsList {
		added, removed := diffStrings(oldList, newList)

		var changes []Change

		for _, v := range added {
			changes = append(changes, Change{Statement: sid, Kind: ConditionWeakening, Description: fmt.Sprintf("~ %s %s allowlist\n    + %s", sid, key, v)})
		}

		for _, v := range removed {
			changes = append(changes, Change{Statement: sid, Kind: ConditionTightening, Description: fmt.Sprintf("~ %s %s allowlist\n    - %s", sid, key, v)})
		}

		return changes
	}

	oldStr := describeValue(oldVal)
	newStr := describeValue(newVal)

	if oldStr == newStr {
		return nil
	}

	kind := ConditionWeakening // conservative default: an unrecognized value change needs review, same fail-closed posture as classify.Unknown

	oldHasWildcard := strings.Contains(oldStr, "*")
	newHasWildcard := strings.Contains(newStr, "*")

	if oldHasWildcard && !newHasWildcard {
		kind = ConditionTightening
	} else if !oldHasWildcard && newHasWildcard {
		kind = ConditionWeakening
	}

	return []Change{{
		Statement:   sid,
		Kind:        kind,
		Description: fmt.Sprintf("~ %s %s changed: %s -> %s", sid, key, oldStr, newStr),
	}}
}

func conditionMap(c *render.Condition) map[string]any {
	if c == nil {
		return nil
	}

	return c.StringEquals
}

func describeValue(v any) string {
	if list, ok := asStringList(v); ok {
		return "[" + strings.Join(list, ", ") + "]"
	}

	return fmt.Sprintf("%v", v)
}

func asStringList(v any) ([]string, bool) {
	switch val := v.(type) {
	case []string:
		return val, true
	case []any:
		out := make([]string, 0, len(val))

		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}

			out = append(out, s)
		}

		return out, true
	default:
		return nil, false
	}
}

// diffStrings returns the elements only in b (added) and only in a
// (removed).
func diffStrings(a, b []string) (added, removed []string) {
	inA := make(map[string]bool, len(a))
	for _, s := range a {
		inA[s] = true
	}

	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}

	for _, s := range b {
		if !inA[s] {
			added = append(added, s)
		}
	}

	for _, s := range a {
		if !inB[s] {
			removed = append(removed, s)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return added, removed
}

func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Statement != changes[j].Statement {
			return changes[i].Statement < changes[j].Statement
		}

		return changes[i].Description < changes[j].Description
	})
}
