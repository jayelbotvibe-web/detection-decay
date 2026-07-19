// Package score implements the DecayScore capability-gate model.
// DecayScore = 1 - P(source_ok)·P(field_ok|source_ok)·P(behavior)
package score

import (
	"fmt"
	"strings"
)

// Verdict labels.
const (
	VHealthy          = "HEALTHY"
	VDegraded         = "DEGRADED"
	VDeadSource       = "DEAD:SOURCE"
	VDeadField        = "DEAD:FIELD"
	VInsufficientData = "INSUFFICIENT_DATA"
)

// Verdict band thresholds — exported so they remain visible and tunable.
const (
	HealthyThreshold = 0.8 // ratio >= this → healthy contribution
	DeadThreshold    = 0.2 // ratio <  this → dead contribution
	// Between DeadThreshold and HealthyThreshold → DEGRADED.
)

// MaxHealthyDecay is the decay score below which HEALTHY is permitted.
// Above this, at least DEGRADED is required.
const MaxHealthyDecay = 0.05

// Evidence is one rule-state measurement row.
type Evidence struct {
	Rule                  string   `json:"rule"`
	State                 string   `json:"state"`
	Liveness              string   `json:"liveness"`
	Volume                int      `json:"volume"`
	BaselineVolume        int      `json:"baseline_volume"`
	FieldPopulate         *float64 `json:"field_populate"`
	BaselineFieldPopulate float64  `json:"baseline_field_populate"`
	Field                 string   `json:"field"`
}

// Result is the scored output for one rule-state.
type Result struct {
	Evidence
	PSource       float64 `json:"p_source"`
	PField        float64 `json:"p_field"`
	PBehavior     float64 `json:"p_behavior"`
	SourceAbstain bool    `json:"source_abstain"`
	FieldAbstain  bool    `json:"field_abstain"`
	Health        float64 `json:"health"`
	DecayScore    float64 `json:"decay_score"`
	Verdict       string  `json:"verdict"`
	Reason        string  `json:"reason"`
}

// Score evaluates a single evidence row.
func Score(ev Evidence) Result {
	r := Result{Evidence: ev, PBehavior: 1.0}

	// --- P(source) — continuous ratio ---
	if !strings.EqualFold(ev.Liveness, "active") {
		r.PSource = 0
	} else if ev.BaselineVolume == 0 {
		// No baseline: abstain so we don't falsely report DEAD:SOURCE.
		r.PSource = 1.0
		r.SourceAbstain = true
	} else {
		ratio := float64(ev.Volume) / float64(ev.BaselineVolume)
		if ratio > 1.0 {
			ratio = 1.0
		}
		if ratio < 0 {
			ratio = 0
		}
		r.PSource = ratio
	}

	// --- P(field) ---
	if ev.FieldPopulate == nil {
		r.FieldAbstain = true
	} else {
		fp := *ev.FieldPopulate
		bfp := ev.BaselineFieldPopulate
		if bfp == 0 {
			bfp = 1.0
		}
		ratio := fp / bfp
		if ratio > 1.0 {
			ratio = 1.0
		}
		if ratio < 0 {
			ratio = 0
		}
		r.PField = ratio
	}

	// --- Health and DecayScore ---
	psource := r.PSource
	if r.SourceAbstain {
		psource = 1.0
	}
	pfield := r.PField
	if r.FieldAbstain {
		pfield = 1.0
	}
	r.Health = psource * pfield * r.PBehavior
	r.DecayScore = 1.0 - r.Health

	// --- Verdict + reason ---
	fieldLabel := ev.Field
	if fieldLabel == "" {
		fieldLabel = "field"
	}

	switch {
	case !strings.EqualFold(ev.Liveness, "active"):
		r.Verdict = VDeadSource
		r.Reason = "agent disconnected"

	case r.FieldAbstain && r.SourceAbstain:
		r.Verdict = VInsufficientData
		r.Reason = "no baseline data — insufficient to evaluate"

	// Source death beats field abstain: if events have stopped,
	// the field being null is a consequence, not the cause.
	case r.PSource < DeadThreshold:
		r.Verdict = VDeadSource
		r.Reason = fmt.Sprintf("volume %d→%d (%.0f%% of baseline) while agent connected — silent log-collection failure",
			ev.BaselineVolume, ev.Volume, r.PSource*100)

	case r.FieldAbstain:
		r.Verdict = VInsufficientData
		r.Reason = fmt.Sprintf("%s data missing — cannot evaluate", fieldLabel)

	case r.PField < DeadThreshold:
		r.Verdict = VDeadField
		r.Reason = fmt.Sprintf("%s populate %.0f%%→%.0f%% (%.0f%% of baseline) while volume nominal — field silently dropped",
			fieldLabel, ev.BaselineFieldPopulate*100, *ev.FieldPopulate*100, r.PField*100)

	case r.PSource < HealthyThreshold || r.PField < HealthyThreshold:
		r.Verdict = VDegraded
		parts := make([]string, 0, 2)
		if r.PField < HealthyThreshold {
			parts = append(parts, fmt.Sprintf("%s at %.0f%% of baseline", fieldLabel, r.PField*100))
		}
		if r.PSource < HealthyThreshold {
			parts = append(parts, fmt.Sprintf("volume at %.0f%% of baseline", r.PSource*100))
		}
		r.Reason = strings.Join(parts, "; ")

	default:
		r.Verdict = VHealthy
		r.Reason = "all links intact"
	}

	// Invariant: never report HEALTHY above MaxHealthyDecay.
	// If the decay score is non-trivial, bump to at least DEGRADED.
	if r.Verdict == VHealthy && r.DecayScore > MaxHealthyDecay {
		r.Verdict = VDegraded
		r.Reason = fmt.Sprintf("decay %.2f exceeds healthy threshold %.2f", r.DecayScore, MaxHealthyDecay)
	}

	return r
}

// ScoreAll evaluates a slice of evidence rows.
func ScoreAll(evs []Evidence) []Result {
	out := make([]Result, len(evs))
	for i, ev := range evs {
		out[i] = Score(ev)
	}
	return out
}
