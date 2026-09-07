package realbench

import (
	"fmt"
	"strings"
)

// ExpectationStability records how consistently one known vulnerability was
// matched across independent runs. On a fixed control, a match is a regression.
type ExpectationStability struct {
	ExpectationID string  `json:"expectation_id"`
	Class         string  `json:"class"`
	Matches       int     `json:"matches"`
	Runs          int     `json:"runs"`
	MatchRate     float64 `json:"match_rate"`
}

// StabilityResult makes stochastic recall explicit instead of allowing one
// lucky run to stand in for scanner reliability.
type StabilityResult struct {
	Suite                      string                 `json:"suite"`
	TargetID                   string                 `json:"target_id"`
	Mode                       string                 `json:"mode"`
	Product                    string                 `json:"product"`
	Version                    string                 `json:"version"`
	Runs                       int                    `json:"runs"`
	Expected                   int                    `json:"expected"`
	MeanTargetedRecall         float64                `json:"mean_targeted_recall"`
	MinimumTargetedRecall      float64                `json:"minimum_targeted_recall"`
	MaximumTargetedRecall      float64                `json:"maximum_targeted_recall"`
	ExpectationsFoundAnyRun    int                    `json:"expectations_found_any_run"`
	ExpectationsFoundEveryRun  int                    `json:"expectations_found_every_run"`
	ControlRunsWithRegressions int                    `json:"control_runs_with_regressions"`
	Stable                     bool                   `json:"stable"`
	Expectations               []ExpectationStability `json:"expectations"`
}

// Aggregate combines independent scores for the same target. It rejects mixed
// targets or structurally different expectation sets so the rates cannot hide
// an invalid comparison.
func Aggregate(results []Result) (StabilityResult, error) {
	if len(results) == 0 {
		return StabilityResult{}, fmt.Errorf("real-world stability requires at least one result")
	}
	first := results[0]
	agg := StabilityResult{
		Suite:                 first.Suite,
		TargetID:              first.TargetID,
		Mode:                  first.Mode,
		Product:               first.Product,
		Version:               first.Version,
		Runs:                  len(results),
		Expected:              first.Expected,
		MinimumTargetedRecall: first.TargetedRecall,
		MaximumTargetedRecall: first.TargetedRecall,
		Expectations:          make([]ExpectationStability, len(first.Expectations)),
	}
	indices := make(map[string]int, len(first.Expectations))
	for i, row := range first.Expectations {
		if row.ExpectationID == "" {
			return StabilityResult{}, fmt.Errorf("result has an empty expectation id")
		}
		if _, exists := indices[row.ExpectationID]; exists {
			return StabilityResult{}, fmt.Errorf("result repeats expectation %q", row.ExpectationID)
		}
		indices[row.ExpectationID] = i
		agg.Expectations[i] = ExpectationStability{
			ExpectationID: row.ExpectationID,
			Class:         row.Class,
			Runs:          len(results),
		}
	}

	for runIndex, result := range results {
		if result.Suite != first.Suite || result.TargetID != first.TargetID ||
			result.Mode != first.Mode || result.Product != first.Product ||
			result.Version != first.Version {
			return StabilityResult{}, fmt.Errorf("result %d belongs to a different benchmark target", runIndex+1)
		}
		if result.Expected != first.Expected || len(result.Expectations) != len(first.Expectations) {
			return StabilityResult{}, fmt.Errorf("result %d has a different expectation set", runIndex+1)
		}

		seen := make(map[string]struct{}, len(result.Expectations))
		for _, row := range result.Expectations {
			index, ok := indices[row.ExpectationID]
			if !ok || agg.Expectations[index].Class != row.Class {
				return StabilityResult{}, fmt.Errorf("result %d has a different expectation set", runIndex+1)
			}
			if _, duplicate := seen[row.ExpectationID]; duplicate {
				return StabilityResult{}, fmt.Errorf("result %d repeats expectation %q", runIndex+1, row.ExpectationID)
			}
			seen[row.ExpectationID] = struct{}{}
			if row.Matched {
				agg.Expectations[index].Matches++
			}
		}

		agg.MeanTargetedRecall += result.TargetedRecall
		if result.TargetedRecall < agg.MinimumTargetedRecall {
			agg.MinimumTargetedRecall = result.TargetedRecall
		}
		if result.TargetedRecall > agg.MaximumTargetedRecall {
			agg.MaximumTargetedRecall = result.TargetedRecall
		}
		if result.ControlRegressions > 0 {
			agg.ControlRunsWithRegressions++
		}
	}

	agg.MeanTargetedRecall /= float64(len(results))
	for i := range agg.Expectations {
		row := &agg.Expectations[i]
		row.MatchRate = float64(row.Matches) / float64(row.Runs)
		if row.Matches > 0 {
			agg.ExpectationsFoundAnyRun++
		}
		if row.Matches == row.Runs {
			agg.ExpectationsFoundEveryRun++
		}
	}
	if agg.Mode == ModeFixedControl {
		agg.Stable = agg.ControlRunsWithRegressions == 0
	} else {
		agg.Stable = agg.ExpectationsFoundEveryRun == agg.Expected
	}
	return agg, nil
}

// String renders the cross-run reliability summary.
func (r StabilityResult) String() string {
	var b strings.Builder
	if r.Mode == ModeFixedControl {
		fmt.Fprintf(&b, "Real-world control stability: %s %s — %d/%d runs had a known-signature regression\n",
			r.Product, r.Version, r.ControlRunsWithRegressions, r.Runs)
	} else {
		fmt.Fprintf(&b, "Real-world recall stability: %s %s — %d run(s), mean %.0f%%, range %.0f–%.0f%%\n",
			r.Product, r.Version, r.Runs, 100*r.MeanTargetedRecall,
			100*r.MinimumTargetedRecall, 100*r.MaximumTargetedRecall)
		fmt.Fprintf(&b, "  Found in every run: %d/%d; found in any run: %d/%d\n",
			r.ExpectationsFoundEveryRun, r.Expected, r.ExpectationsFoundAnyRun, r.Expected)
	}
	for _, row := range r.Expectations {
		fmt.Fprintf(&b, "  %s (%s): %d/%d matches (%.0f%%)\n",
			row.ExpectationID, row.Class, row.Matches, row.Runs, 100*row.MatchRate)
	}
	return b.String()
}
