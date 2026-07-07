// Package score implements the DecayScore capability-gate model.
// DecayScore = 1 - P(source_ok)·P(field_ok|source_ok)·P(behavior)
package score

import "fmt"

// Verdict labels.
const (
	VHealthy          = "HEALTHY"
	VDeadSource       = "DEAD:SOURCE"
	VDeadField        = "DEAD:FIELD"
	VInsufficientData = "INSUFFICIENT_DATA"
	VProbeError       = "PROBE_ERROR"
)

// Evidence is one rule-state measurement row.
type Evidence struct {
	Rule                  string   `json:"rule"`
	State                 string   `json:"state"`
	Liveness              string   `json:"liveness"`
	Volume                int      `json:"volume"`
	BaselineVolume        int      `json:"baseline_volume"`
	FieldPopulate         *float64 `json:"field_populate"`
	BaselineFieldPopulate float64  `json:"baseline_field_populate"`
	ProbeError            string   `json:"probe_error,omitempty"`
}

// Result is the scored output for one rule-state.
type Result struct {
	Evidence
	PSource      float64 `json:"p_source"`
	PField       float64 `json:"p_field"`
	PBehavior    float64 `json:"p_behavior"`
	FieldAbstain bool    `json:"field_abstain"`
	Health       float64 `json:"health"`
	DecayScore   float64 `json:"decay_score"`
	Verdict      string  `json:"verdict"`
	Reason       string  `json:"reason"`
}

// Score evaluates a single evidence row.
// PROBE_ERROR is checked FIRST — a failed measurement is NEVER scored as DEAD.
func Score(ev Evidence) Result {
	r := Result{Evidence: ev, PBehavior: 1.0}

	// PROBE_ERROR gate: a failed measurement is never scored as DEAD.
	if ev.ProbeError != "" {
		r.Verdict = VProbeError
		r.DecayScore = -1 // sentinel: n/a
		r.Reason = ev.ProbeError
		return r
	}

	// P_source
	if ev.Liveness != "active" {
		r.PSource = 0
	} else if ev.Volume == 0 || (ev.BaselineVolume > 0 && float64(ev.Volume) < 0.1*float64(ev.BaselineVolume)) {
		r.PSource = 0
	} else {
		r.PSource = 1.0
	}

	// P_field
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

	// Health and DecayScore
	pfield := r.PField
	if r.FieldAbstain {
		pfield = 1.0
	}
	r.Health = r.PSource * pfield * r.PBehavior
	r.DecayScore = 1.0 - r.Health

	// Verdict + reason
	switch {
	case ev.Liveness != "active":
		r.Verdict = VDeadSource
		r.Reason = "agent disconnected"
	case r.PSource == 0:
		r.Verdict = VDeadSource
		r.Reason = fmt.Sprintf("volume %d→%d while agent connected — silent log-collection failure", ev.BaselineVolume, ev.Volume)
	case r.FieldAbstain:
		r.Verdict = VInsufficientData
		r.Reason = "field data missing — cannot evaluate"
	case r.PField == 0:
		r.Verdict = VDeadField
		r.Reason = fmt.Sprintf("Image populate %.0f%%→%.0f%% while volume nominal — field silently dropped", ev.BaselineFieldPopulate*100, *ev.FieldPopulate*100)
	default:
		r.Verdict = VHealthy
		r.Reason = "all links intact"
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
