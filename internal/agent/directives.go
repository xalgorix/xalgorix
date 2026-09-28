// Package agent — directives.go fixes a structural delivery bug in the hook
// system: HookRegistry.Fire previously merged hook results with a
// first-non-empty-nudge-wins rule, so when several OnIterationStart hooks
// each produced a nudge, only the FIRST registered hook's message reached the
// model — while every hook had already mutated its own "I delivered" state.
// The skill suggester marked its recommendation sent, the planner recorded its
// brief as injected, and the delegation coordinator reserved its one-shot
// nudge; none of it was actually delivered. The planner brief was then
// permanently suppressed (LastPlanBrief already matched) and skill guidance
// was lost for the rest of the scan.
//
// Directives are the fix: hooks return structured, prioritized, deduped
// guidance units and Fire composes ALL of them centrally. A directive's
// producing hook marks its state delivered ONLY via the OnDelivered callback,
// which Fire runs after the content is verifiably part of the merged nudge.
// A directive dropped by dedupe or the length cap stays eligible for delivery
// on a later iteration.
package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Directive is one model-facing guidance unit produced by a hook (typically
// OnIterationStart). Priority orders composition (lower = more important);
// Category names the producing subsystem for observability; DedupeKey
// collapses repeated directives within one composition; OnDelivered is the
// ONLY place a hook may mark its guidance as delivered.
type Directive struct {
	Priority  int
	Category  string
	DedupeKey string
	Content   string
	// OnDelivered runs when this directive's content is verifiably part of the
	// composed message injected into the conversation. Never fire side-effect
	// state from the hook body for guidance the model may never see.
	OnDelivered func(*ScanState)
}

// Directive priority bands. Critical instructions change what the agent must
// do right now (delegation launch, missing-inventory blocker); planner context
// is the persistent what-to-work-on brief; advisory hints (skill
// recommendations) enrich but never redirect.
const (
	DirectivePriorityCritical = 10
	DirectivePriorityPlanner  = 20
	DirectivePriorityAdvisory = 30
	DirectivePriorityLegacy   = 40
)

// maxDirectiveComposeLen bounds the total composed nudge so composing several
// directives cannot flood the context. Overflow drops the LOWEST-priority
// directives first (from the tail) and never drops the highest-priority one;
// dropped directives simply return on a later iteration because their
// OnDelivered never ran.
const maxDirectiveComposeLen = 12000

// composeDirectives merges directives from every hook on an event into one
// model-facing message. Rules:
//   - empty-content directives are dropped;
//   - duplicate DedupeKeys collapse (first wins, later ones stay eligible
//     because their OnDelivered is not invoked);
//   - stable sort by Priority ascending (critical first);
//   - a legacy non-empty Nudge is appended at the end unless identical to a
//     directive already included, preserving old single-nudge hooks;
//   - overflow trims the tail (lowest priority) with a marker.
//
// It returns the composed message and the directives that were actually
// delivered (their OnDelivered must run). Composition is deterministic for a
// given input slice.
func composeDirectives(dirs []Directive, legacyNudge string) (string, []Directive) {
	kept := make([]Directive, 0, len(dirs)+1)
	seen := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		if strings.TrimSpace(d.Content) == "" {
			continue
		}
		if d.DedupeKey != "" {
			if seen[d.DedupeKey] {
				continue
			}
			seen[d.DedupeKey] = true
		}
		kept = append(kept, d)
	}
	if len(kept) == 0 {
		return legacyNudge, nil
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].Priority < kept[j].Priority
	})
	if legacyNudge != "" {
		duplicate := false
		for _, d := range kept {
			if d.Content == legacyNudge {
				duplicate = true
				break
			}
		}
		if !duplicate {
			kept = append(kept, Directive{
				Priority: DirectivePriorityLegacy,
				Category: "legacy",
				Content:  legacyNudge,
			})
		}
	}

	delivered := kept
	dropped := 0
	for directiveLen(delivered) > maxDirectiveComposeLen && len(delivered) > 1 {
		delivered = delivered[:len(delivered)-1]
		dropped++
	}

	parts := make([]string, 0, len(delivered)+1)
	for _, d := range delivered {
		parts = append(parts, d.Content)
	}
	if dropped > 0 {
		parts = append(parts, fmt.Sprintf("… (%d lower-priority directive(s) deferred to a later iteration)", dropped))
	}
	return strings.Join(parts, "\n\n"), delivered
}

// directiveLen sums the content length of the directives plus separators.
func directiveLen(dirs []Directive) int {
	total := 0
	for _, d := range dirs {
		total += len(d.Content) + 2
	}
	return total
}
