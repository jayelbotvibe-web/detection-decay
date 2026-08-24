// Package score implements the DecayScore capability-gate model.
// DecayScore = 1 - P(source_ok)·P(field_ok|source_ok)·P(behavior)
package score

import (
	"crypto/sha256"
	"encoding/hex"
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
	VProbeError       = "PROBE_ERROR"
)

// Verdict band thresholds — exported so they remain visible and tunable.
const (
	HealthyThreshold = 0.8 // gate value >= this → healthy contribution
	DeadThreshold    = 0.2 // gate value <  this → dead contribution
	// Between DeadThreshold and HealthyThreshold → DEGRADED.

	// OverThreshold is the volume ratio above which a source is treated as
	// over-collecting rather than healthy. Volume between 1x and 3x baseline is
	// normal variance and clamps to 1.0; beyond that, flooding degrades
	// detection through drops, rule timeouts and alert-queue backlog.
	OverThreshold = 3.0
	// OverFloor bounds the over-collection penalty. Events are demonstrably
	// flowing, so over-collection can degrade a source but must never read as
	// dead — the floor sits at DeadThreshold, not below it.
	OverFloor = DeadThreshold
)

// Confidence bands and inputs.
const (
	ConfHigh = 0.8 // confidence >= this → HIGH
	ConfMed  = 0.5 // confidence >= this → MEDIUM

	// MinSample is the baseline event count below which a measurement is
	// treated as statistically thin. A rule that normally fires twice a window
	// cannot distinguish a real outage from a quiet afternoon.
	MinSample = 30

	// StaleBaselineSeconds is the age beyond which a baseline is discounted.
	// Telemetry volume drifts with deployment and seasonality, so an old
	// baseline measures history rather than health.
	StaleBaselineSeconds = 30 * 24 * 60 * 60
)

// Confidence labels.
const (
	CHigh   = "HIGH"
	CMedium = "MEDIUM"
	CLow    = "LOW"
)

// MaxHealthyDecay is the decay score below which HEALTHY is permitted.
// Above this, at least DEGRADED is required.
//
// Note this is a tighter bar than HealthyThreshold: a row needs
// P(source)·P(field)·P(behavior) >= 1-MaxHealthyDecay (0.95) to read HEALTHY,
// not merely every gate >= HealthyThreshold (0.8). The ceiling is the binding
// constraint and the README gate table documents it as such.
const MaxHealthyDecay = 0.05

// Gate bands.
const (
	BandHealthy  = "healthy"
	BandDegraded = "degraded"
	BandDead     = "dead"
	BandOver     = "over"
	BandAbstain  = "abstain"
)

// Contribution is a single (reason, value) factor that determined a gate.
//
// A gate's value is the product of its contributions, and its human-readable
// explanation is rendered from these same values — so the breakdown always
// reconciles with the number it explains. Values are multiplicative because
// the gates are probabilities, not point scores.
type Contribution struct {
	Reason string  `json:"reason"`
	Value  float64 `json:"value"`
}

// Gate is one link in the capability chain.
type Gate struct {
	Name    string         `json:"name"`
	Value   float64        `json:"value"`
	Band    string         `json:"band"`
	Abstain bool           `json:"abstain"`
	Factors []Contribution `json:"factors"`
}

// product returns the product of a gate's contribution values.
// An empty factor list is the identity, 1.0.
func (g Gate) product() float64 {
	v := 1.0
	for _, f := range g.Factors {
		v *= f.Value
	}
	return v
}

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

	// BaselineAgeSeconds is how old the baseline measurement is. Optional; zero
	// means unknown and is not penalised.
	BaselineAgeSeconds int `json:"baseline_age_seconds,omitempty"`

	// ProbeError, when non-empty, means the measurement itself failed. A failed
	// probe must never be reported as a detection outage — that is the worst
	// possible error for this tool, since it pages an operator about telemetry
	// that may be perfectly healthy.
	ProbeError string `json:"probe_error,omitempty"`
}

// Result is the scored output for one rule-state.
type Result struct {
	Evidence

	// PSource, PField and PBehavior mirror the corresponding Gate values and
	// are retained as a flat, machine-readable surface. Gates is the source of
	// truth; these are projections of it.
	PSource   float64 `json:"p_source"`
	PField    float64 `json:"p_field"`
	PBehavior float64 `json:"p_behavior"`

	SourceAbstain bool `json:"source_abstain"`
	FieldAbstain  bool `json:"field_abstain"`

	Gates []Gate `json:"gates"`

	// Confidence is orthogonal to the verdict and is deliberately NOT folded
	// into Health. The verdict says how bad; confidence says how sure. Routing
	// and alerting key on the pair, so a confident DEGRADED and a shaky
	// DEAD:SOURCE can be handled differently.
	Confidence      Gate    `json:"confidence"`
	ConfidenceLabel string  `json:"confidence_label"`
	ConfidenceScore float64 `json:"confidence_score"`

	// Fingerprint identifies this finding across runs. See Result.fingerprint.
	Fingerprint string `json:"fingerprint"`

	Health      float64 `json:"health"`
	DecayScore  float64 `json:"decay_score"`
	Verdict     string  `json:"verdict"`
	Reason      string  `json:"reason"`
	Explanation string  `json:"explanation"`
}

// fieldLabel returns the field name for prose, with a neutral fallback so
// evidence files written before the "field" key existed still read sensibly.
func fieldLabel(ev Evidence) string {
	if ev.Field == "" {
		return "field"
	}
	return ev.Field
}

// bandFor classifies a gate value into a verdict band.
func bandFor(v float64) string {
	switch {
	case v < DeadThreshold:
		return BandDead
	case v < HealthyThreshold:
		return BandDegraded
	default:
		return BandHealthy
	}
}

// clamp01 bounds a ratio to [0,1].
func clamp01(v float64) float64 {
	if v > 1 {
		return 1
	}
	if v < 0 {
		return 0
	}
	return v
}

// sourceGate measures whether telemetry is still arriving.
func sourceGate(ev Evidence) Gate {
	g := Gate{Name: "source"}

	if !strings.EqualFold(ev.Liveness, "active") {
		g.Factors = []Contribution{{
			Reason: fmt.Sprintf("agent liveness %q — not active", ev.Liveness),
			Value:  0,
		}}
		g.Value, g.Band = 0, BandDead
		return g
	}

	if ev.BaselineVolume == 0 {
		g.Abstain = true
		g.Factors = []Contribution{{
			Reason: "no volume baseline recorded — source gate abstained",
			Value:  1.0,
		}}
		g.Value, g.Band = 1.0, BandAbstain
		return g
	}

	ratio := float64(ev.Volume) / float64(ev.BaselineVolume)

	// Over-collection: events are flowing, but far more than baseline. A lost
	// ingest filter or duplicated pipeline is a silent failure in the same
	// family as source death, and volume-only monitors miss it just as badly.
	if ratio > OverThreshold {
		v := OverThreshold / ratio
		if v < OverFloor {
			v = OverFloor
		}
		g.Factors = []Contribution{{
			Reason: fmt.Sprintf("volume %d vs baseline %d = %.0f%% of baseline — over-collection (lost filter, duplicate ingest, or log flooding)",
				ev.Volume, ev.BaselineVolume, ratio*100),
			Value: v,
		}}
		g.Value, g.Band = v, BandOver
		return g
	}

	// Between 1x and OverThreshold is normal variance, not extra health.
	ratio = clamp01(ratio)
	g.Factors = []Contribution{{
		Reason: fmt.Sprintf("volume %d vs baseline %d = %.0f%% of baseline",
			ev.Volume, ev.BaselineVolume, ratio*100),
		Value: ratio,
	}}
	g.Value, g.Band = ratio, bandFor(ratio)
	return g
}

// fieldGate measures whether the field a rule depends on is still populated.
func fieldGate(ev Evidence) Gate {
	g := Gate{Name: "field"}
	label := fieldLabel(ev)

	if ev.FieldPopulate == nil {
		g.Abstain = true
		g.Factors = []Contribution{{
			Reason: fmt.Sprintf("%s populate rate not measured — field gate abstained", label),
			Value:  1.0,
		}}
		g.Value, g.Band = 1.0, BandAbstain
		return g
	}

	fp := *ev.FieldPopulate
	bfp := ev.BaselineFieldPopulate
	if bfp == 0 {
		bfp = 1.0
	}
	ratio := clamp01(fp / bfp)

	g.Factors = []Contribution{{
		Reason: fmt.Sprintf("%s populate %.0f%% vs baseline %.0f%% = %.0f%% of baseline",
			label, fp*100, bfp*100, ratio*100),
		Value: ratio,
	}}
	g.Value, g.Band = ratio, bandFor(ratio)
	return g
}

// confidenceGate measures how much weight the verdict deserves. It never
// changes the verdict — an operator needs to know that a source looks dead AND
// that the measurement behind that claim is thin.
func confidenceGate(ev Evidence, gates []Gate) Gate {
	g := Gate{Name: "confidence"}

	// Sample size is judged on the baseline, not the current volume: during a
	// real outage the current volume is zero, and that is the finding, not a
	// reason to doubt it.
	switch {
	case ev.BaselineVolume <= 0:
		g.Factors = append(g.Factors, Contribution{
			Reason: "no baseline volume to size the sample", Value: 0.5})
	case ev.BaselineVolume < MinSample:
		v := 0.5 + 0.5*float64(ev.BaselineVolume)/MinSample
		g.Factors = append(g.Factors, Contribution{
			Reason: fmt.Sprintf("thin sample — baseline of %d events is below the %d-event floor",
				ev.BaselineVolume, MinSample), Value: v})
	default:
		g.Factors = append(g.Factors, Contribution{
			Reason: fmt.Sprintf("baseline of %d events clears the %d-event sample floor",
				ev.BaselineVolume, MinSample), Value: 1.0})
	}

	for _, gate := range gates {
		if gate.Abstain {
			g.Factors = append(g.Factors, Contribution{
				Reason: fmt.Sprintf("%s gate abstained — one link unmeasured", gate.Name), Value: 0.5})
		}
	}

	if ev.BaselineAgeSeconds > StaleBaselineSeconds {
		g.Factors = append(g.Factors, Contribution{
			Reason: fmt.Sprintf("baseline is %d days old — volume drifts with deployment and seasonality",
				ev.BaselineAgeSeconds/86400), Value: 0.6})
	}

	g.Value = g.product()
	return g
}

// confidenceLabel bands a confidence value.
func confidenceLabel(v float64) string {
	switch {
	case v >= ConfHigh:
		return CHigh
	case v >= ConfMed:
		return CMedium
	default:
		return CLow
	}
}

// behaviorGate is the third link: rule-match freshness. Not yet modeled, and
// held at 1.0 so it cannot influence a verdict it did not measure.
func behaviorGate() Gate {
	return Gate{
		Name:  "behavior",
		Value: 1.0,
		Band:  BandHealthy,
		Factors: []Contribution{{
			Reason: "rule-match freshness not yet modeled — gate held at 1.0",
			Value:  1.0,
		}},
	}
}

// shortfall names every gate falling below bar, using the gate's own factor
// reasons so the verdict prose always carries the measurement behind it.
func shortfall(gates []Gate, bar float64) string {
	parts := make([]string, 0, len(gates))
	for _, g := range gates {
		if g.Abstain || g.Value >= bar {
			continue
		}
		for _, f := range g.Factors {
			parts = append(parts, f.Reason)
		}
	}
	return strings.Join(parts, "; ")
}

// Score evaluates a single evidence row.
func Score(ev Evidence) Result {
	r := Result{Evidence: ev}

	// A failed measurement is not a detection outage. Short-circuit before any
	// gate is built so a probe failure can never masquerade as DEAD:SOURCE.
	if ev.ProbeError != "" {
		g := Gate{
			Name: "probe", Value: 1.0, Band: BandAbstain, Abstain: true,
			Factors: []Contribution{{
				Reason: fmt.Sprintf("measurement failed: %s", ev.ProbeError),
				Value:  1.0,
			}},
		}
		r.Gates = []Gate{g}
		r.Confidence = Gate{Name: "confidence", Value: 0, Band: BandDead,
			Factors: []Contribution{{Reason: "the probe failed — nothing was measured", Value: 0}}}
		r.ConfidenceScore, r.ConfidenceLabel = 0, CLow
		r.PSource, r.PField, r.PBehavior = 1.0, 1.0, 1.0
		r.SourceAbstain, r.FieldAbstain = true, true
		r.Health, r.DecayScore = 1.0, 0.0
		r.Verdict = VProbeError
		r.Reason = fmt.Sprintf("measurement failed: %s — detection health unknown", ev.ProbeError)
		r.Fingerprint = fingerprint(r)
		r.Explanation = explain(r)
		return r
	}

	src := sourceGate(ev)
	fld := fieldGate(ev)
	bhv := behaviorGate()
	r.Gates = []Gate{src, fld, bhv}

	r.PSource, r.PField, r.PBehavior = src.Value, fld.Value, bhv.Value
	r.SourceAbstain, r.FieldAbstain = src.Abstain, fld.Abstain

	r.Confidence = confidenceGate(ev, r.Gates)
	r.Confidence.Band = bandFor(r.Confidence.Value)
	r.ConfidenceScore = r.Confidence.Value
	r.ConfidenceLabel = confidenceLabel(r.Confidence.Value)

	// Confidence is NOT a factor here. It qualifies the verdict, it does not
	// change it — folding it in would let a thin sample look like good health.
	r.Health = src.Value * fld.Value * bhv.Value
	r.DecayScore = 1.0 - r.Health

	label := fieldLabel(ev)

	switch {
	case !strings.EqualFold(ev.Liveness, "active"):
		r.Verdict = VDeadSource
		r.Reason = "agent disconnected"

	case src.Abstain && fld.Abstain:
		r.Verdict = VInsufficientData
		r.Reason = "no baseline data — insufficient to evaluate"

	// Source abstention alone: no baseline volume means we can't evaluate the
	// source gate. Zero events with no baseline is never healthy evidence.
	case src.Abstain:
		r.Verdict = VInsufficientData
		r.Reason = "no source baseline — insufficient to evaluate"

	// Source death beats field abstain: if events have stopped, the field being
	// null is a consequence, not the cause.
	case src.Band == BandDead:
		r.Verdict = VDeadSource
		r.Reason = fmt.Sprintf("volume %d→%d (%.0f%% of baseline) while agent connected — silent log-collection failure",
			ev.BaselineVolume, ev.Volume, src.Value*100)

	case fld.Abstain:
		r.Verdict = VInsufficientData
		r.Reason = fmt.Sprintf("%s data missing — cannot evaluate", label)

	case fld.Band == BandDead:
		r.Verdict = VDeadField
		r.Reason = fmt.Sprintf("%s populate %.0f%%→%.0f%% (%.0f%% of baseline) while volume nominal — field silently dropped",
			label, ev.BaselineFieldPopulate*100, *ev.FieldPopulate*100, fld.Value*100)

	case src.Band == BandOver:
		r.Verdict = VDegraded
		r.Reason = shortfall(r.Gates, 1.0)

	case src.Band == BandDegraded || fld.Band == BandDegraded:
		r.Verdict = VDegraded
		r.Reason = shortfall(r.Gates, HealthyThreshold)

	default:
		r.Verdict = VHealthy
		r.Reason = "all links intact"
	}

	// Invariant: never report HEALTHY above MaxHealthyDecay. Every gate can sit
	// above HealthyThreshold and still compound past the ceiling, so this is a
	// real band, not dead code.
	//
	// It appends to the specific per-gate detail rather than replacing it — an
	// operator needs to know *which* gate slipped, not just that a threshold
	// was crossed.
	if r.Verdict == VHealthy && r.DecayScore > MaxHealthyDecay {
		r.Verdict = VDegraded
		detail := shortfall(r.Gates, 1.0)
		if detail == "" {
			detail = "gates nominal individually but compounding"
		}
		r.Reason = fmt.Sprintf("%s — decay %.2f exceeds healthy ceiling %.2f",
			detail, r.DecayScore, MaxHealthyDecay)
	}

	r.Fingerprint = fingerprint(r)
	r.Explanation = explain(r)
	return r
}

// FingerprintPrecision is the number of decimal places the decay score is
// rounded to inside a fingerprint. Ordinary measurement noise (0.50 one hour,
// 0.52 the next) must not read as a state change, or every run reports churn
// and the diff becomes as noisy as the full table it replaces.
const FingerprintPrecision = 1

// fingerprint identifies a finding across runs.
//
// The verdict and the banded decay score are inside the hash, so an unchanged
// rule re-fingerprints identically and a rule that got worse produces a new
// one. That is the whole of state-change detection — no diffing code, no
// previous-state bookkeeping. Borrowed from threat-intel-arbiter's dedup key.
func fingerprint(r Result) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%.*f", r.Rule, r.State, r.Verdict, FingerprintPrecision, r.DecayScore)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// explain renders the per-gate breakdown and restates the final arithmetic with
// the actual operands, so a reader can verify the score by hand.
func explain(r Result) string {
	var b strings.Builder
	operands := make([]string, 0, len(r.Gates))

	for _, g := range r.Gates {
		note := ""
		if g.Abstain {
			note = " (abstained)"
		}
		b.WriteString(fmt.Sprintf("P(%s): %.2f%s\n", g.Name, g.Value, note))
		if len(g.Factors) == 0 {
			b.WriteString("  • No contributing factors\n")
		}
		for _, f := range g.Factors {
			b.WriteString(fmt.Sprintf("  • %s (×%.2f)\n", f.Reason, f.Value))
		}
		operands = append(operands, fmt.Sprintf("%.2f", g.Value))
	}

	b.WriteString(fmt.Sprintf("\nDecayScore: 1 - (%s) = %.2f → %s\n",
		strings.Join(operands, " × "), r.DecayScore, r.Verdict))
	b.WriteString(fmt.Sprintf("  %s\n", r.Reason))

	b.WriteString(fmt.Sprintf("\nConfidence (%s): %.2f — does not affect the score above\n",
		r.ConfidenceLabel, r.ConfidenceScore))
	for _, f := range r.Confidence.Factors {
		b.WriteString(fmt.Sprintf("  • %s (×%.2f)\n", f.Reason, f.Value))
	}
	return b.String()
}

// ScoreAll evaluates a slice of evidence rows.
func ScoreAll(evs []Evidence) []Result {
	out := make([]Result, len(evs))
	for i, ev := range evs {
		out[i] = Score(ev)
	}
	return out
}
