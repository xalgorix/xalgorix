// Package agent — skill_runtime.go makes skill loading first-class runtime
// state instead of a blind counter. Previously SkillsLoaded incremented on
// every read_skill tool CALL (before execution, so failed lookups counted),
// duplicates inflated the count, and ANY single load globally suppressed all
// later skill recommendations. The runtime now tracks each successfully
// loaded canonical skill with its request context, and recommendations are
// driven by uncovered per-technology work, never by a scan-wide boolean.
package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools/skills"
)

// LoadedSkillInfo records one successfully loaded canonical skill: what was
// requested, why, and when. Reload-after-context-prune does not create a new
// record (the canonical name is the key); a suppressed duplicate load is
// visible in Reloads without inflating the unique count.
type LoadedSkillInfo struct {
	Name          string // canonical skill name
	RequestedName string // name as first requested (may be an alias)
	Reason        string // "model-requested" or the engine attribution
	TaskRef       string // plan task / hypothesis that requested it, if any
	Iteration     int
	Reloads       int
}

// ── hookSkillLoadTracker ─────────────────────────────────────────────────────
// OnToolResult: counts successful canonical skill loads only. A read_skill
// that errored (unknown name) records a failed lookup; a suppressed duplicate
// records a reload; a re-injection after context pruning does not inflate the
// unique-skill count. SkillsLoaded stays a derived int for backward
// compatibility with the finish-gate note and telemetry.
func hookSkillLoadTracker(state *ScanState, args map[string]string) HookResult {
	if state == nil || args["tool_name"] != "read_skill" {
		return HookResult{}
	}
	if args["error"] != "" {
		state.FailedSkillLoads++
		return HookResult{}
	}
	name := strings.TrimSpace(args["skill_name"])
	if name == "" {
		// Older tool binaries do not tag results with the canonical name; fall
		// back to the requested name rather than not counting the load at all.
		name = strings.TrimSpace(args["name"])
	}
	if name == "" {
		return HookResult{}
	}
	if state.LoadedSkills == nil {
		state.LoadedSkills = make(map[string]*LoadedSkillInfo)
	}
	if rec, exists := state.LoadedSkills[name]; exists {
		if args["skill_duplicate"] == "true" {
			rec.Reloads++
		}
		// Any way you slice it, this is not a NEW skill.
		state.SkillsLoaded = len(state.LoadedSkills)
		return HookResult{}
	}
	state.LoadedSkills[name] = &LoadedSkillInfo{
		Name:          name,
		RequestedName: strings.TrimSpace(args["name"]),
		Reason:        "model-requested",
		Iteration:     state.Iteration,
	}
	state.SkillsLoaded = len(state.LoadedSkills)
	return HookResult{}
}

// ── skill recommendations ─────────────────────────────────────────────────────

// skillRecommendation is one verified, loadable methodology suggestion.
type skillRecommendation struct {
	Skill  string // canonical skill name (resolver-verified to exist)
	Reason string // model-facing justification
}

// techSkillQueries maps DETECTED technologies (hookTechDetector keys) to the
// concept queries that resolve their testing methodology. Queries, not
// hardcoded skill names, so recommendations follow the catalog and its
// aliases as they evolve.
var techSkillQueries = map[string]string{
	"php":        "sql injection",
	"nodejs":     "prototype pollution",
	"java":       "ssti",
	"python":     "ssti",
	"ruby":       "ruby",
	"aspnet":     "sql injection",
	"graphql":    "graphql",
	"firebase":   "firebase",
	"cloudflare": "cloudflare",
}

// recommendedSkillsForState derives loadable methodology suggestions from
// detected technologies and WAF presence. A skill is suggested only when it
// (a) resolves to a real catalog entry, (b) has not been successfully loaded,
// and (c) has not already been recommended (delivered) before. This is what
// turns the old "any one skill load stops all suggestions" behavior into
// per-domain guidance driven by uncovered work.
func recommendedSkillsForState(state *ScanState) []skillRecommendation {
	if state == nil {
		return nil
	}
	var out []skillRecommendation
	seen := make(map[string]bool)
	add := func(query, reason string) {
		skill, ok := skills.ResolveSkillName(query)
		if !ok || seen[skill] || skillCovered(state, skill) {
			return
		}
		seen[skill] = true
		out = append(out, skillRecommendation{Skill: skill, Reason: reason})
	}
	for tech := range state.DetectedTechs {
		if query, ok := techSkillQueries[tech]; ok {
			add(query, "detected "+tech+" stack")
		}
	}
	if state.WAFDetected {
		add("xss", "WAF bypass payloads for the detected firewall")
		add("sql injection", "WAF bypass payloads for the detected firewall")
	}
	// Task-driven recommendations: the next READY plan lane names the
	// methodology the root needs now, so skill loading follows the work
	// instead of only technology detection. Bounded to the current lane
	// (up to 3), never a catalog dump — with zero specialists this is the
	// primary discovery path for class methodology.
	if state.Plan != nil {
		for _, t := range state.Plan.NextTasks(3) {
			if t.VulnClass == "" {
				continue
			}
			if query, ok := VulnClassSkill(t.VulnClass); ok && query != "" {
				add(query, "next plan lane: "+t.ID)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Skill < out[j].Skill })
	return out
}

// skillCovered reports whether a skill is either already loaded or already
// recommended (delivered) — both cases make a re-suggestion noise rather than
// help.
func skillCovered(state *ScanState, skill string) bool {
	if state == nil {
		return false
	}
	if state.LoadedSkills != nil && state.LoadedSkills[skill] != nil {
		return true
	}
	return state.SkillSuggestionsSent[skill]
}

// LoadedSkillNames returns the sorted canonical names of successfully loaded
// skills — the telemetry/finish-gate view of skill usage.
func LoadedSkillNames(state *ScanState) []string {
	if state == nil || len(state.LoadedSkills) == 0 {
		return nil
	}
	names := make([]string, 0, len(state.LoadedSkills))
	for name := range state.LoadedSkills {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var _ = fmt.Sprintf // keep fmt for future engine-attributed loads
