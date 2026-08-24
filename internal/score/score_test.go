package score

import (
	"math"
	"strings"
	"testing"
)

func TestInsufficientData(t *testing.T) {
	fp := 1.0 // non-null, healthy
	ev := Evidence{
		Rule:                  "r.yml",
		Liveness:              "active",
		Volume:                100,
		BaselineVolume:        100,
		FieldPopulate:         nil, // null → field data missing
		BaselineFieldPopulate: fp,
	}
	r := Score(ev)
	if r.Verdict != VInsufficientData {
		t.Errorf("expected INSUFFICIENT_DATA for null field, got %s", r.Verdict)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("expected decay 0.00 (abstain), got %.2f", r.DecayScore)
	}
}

func TestHealthy(t *testing.T) {
	fp := 1.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                64,
		BaselineVolume:        64,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: fp,
	}
	r := Score(ev)
	if r.Verdict != VHealthy {
		t.Errorf("expected HEALTHY, got %s", r.Verdict)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("expected decay 0.00, got %.2f", r.DecayScore)
	}
}

func TestDeadSource(t *testing.T) {
	fp := 1.0
	ev := Evidence{
		Rule:                  "r.yml",
		Liveness:              "active",
		Volume:                0,
		BaselineVolume:        64,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: fp,
	}
	r := Score(ev)
	if r.Verdict != VDeadSource {
		t.Errorf("expected DEAD:SOURCE, got %s", r.Verdict)
	}
	if r.DecayScore != 1.0 {
		t.Errorf("expected decay 1.00, got %.2f", r.DecayScore)
	}
}

func TestDeadField(t *testing.T) {
	fp := 0.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                234,
		BaselineVolume:        64,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VDeadField {
		t.Errorf("expected DEAD:FIELD, got %s", r.Verdict)
	}
	if r.DecayScore != 1.0 {
		t.Errorf("expected decay 1.00, got %.2f", r.DecayScore)
	}
}

func TestPartialDriftField(t *testing.T) {
	// Regression: field at 5% of baseline must NOT report HEALTHY.
	// This is the common production failure — schema changes affecting
	// a subset of events.
	fp := 0.05
	ev := Evidence{
		Rule:                  "partial_drift.yml",
		State:                 "drift",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                200,
		BaselineVolume:        200,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict == VHealthy {
		t.Errorf("partial drift (field 5%%) must NOT be HEALTHY, got %s", r.Verdict)
	}
	if r.DecayScore < 0.9 {
		t.Errorf("partial drift (field 5%%) should have high decay, got %.2f", r.DecayScore)
	}
	if r.PField != 0.05 {
		t.Errorf("PField should be 0.05, got %.2f", r.PField)
	}
}

func TestVolumeCliff(t *testing.T) {
	// Regression: 89% volume collapse must NOT score HEALTHY.
	fp := 1.0
	ev := Evidence{
		Rule:                  "volume_cliff.yml",
		State:                 "cliff",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                22,
		BaselineVolume:        200,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict == VHealthy {
		t.Errorf("volume cliff (11%% of baseline) must NOT be HEALTHY, got %s", r.Verdict)
	}
	if r.DecayScore < 0.85 {
		t.Errorf("volume cliff should have high decay, got %.2f", r.DecayScore)
	}
}

func TestDegradedSource(t *testing.T) {
	// Source at 50% of baseline → DEGRADED.
	fp := 1.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                50,
		BaselineVolume:        100,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VDegraded {
		t.Errorf("expected DEGRADED for 50%% volume, got %s", r.Verdict)
	}
	if r.DecayScore < 0.45 || r.DecayScore > 0.55 {
		t.Errorf("expected decay ~0.50 for 50%% source, got %.2f", r.DecayScore)
	}
}

func TestDegradedField(t *testing.T) {
	// Field at 50% of baseline → DEGRADED.
	fp := 0.5
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "CommandLine",
		Liveness:              "active",
		Volume:                100,
		BaselineVolume:        100,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VDegraded {
		t.Errorf("expected DEGRADED for 50%% field, got %s", r.Verdict)
	}
	if r.DecayScore < 0.45 || r.DecayScore > 0.55 {
		t.Errorf("expected decay ~0.50 for 50%% field, got %.2f", r.DecayScore)
	}
}

func TestNoBaselineInsufficientData(t *testing.T) {
	// Regression: volume=0 + baseline=0 → DEAD:SOURCE was wrong.
	// A newly deployed rule with no baseline should be INSUFFICIENT_DATA.
	ev := Evidence{
		Rule:                  "new_rule.yml",
		Liveness:              "active",
		Volume:                0,
		BaselineVolume:        0,
		FieldPopulate:         nil,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VInsufficientData {
		t.Errorf("expected INSUFFICIENT_DATA for no-baseline, got %s", r.Verdict)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("expected decay 0.00 (abstain both), got %.2f", r.DecayScore)
	}
}

func TestSourceAbstainAloneInsufficientData(t *testing.T) {
	// Regression: source abstain alone (baseline_volume=0, field healthy)
	// must yield INSUFFICIENT_DATA, not HEALTHY.
	// The collector can't produce this row but the scorer is a public API.
	fp := 1.0
	ev := Evidence{
		Rule:                  "newrule.yml",
		State:                 "no baseline",
		Liveness:              "active",
		Volume:                0,
		BaselineVolume:        0,
		Field:                 "src_ip",
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VInsufficientData {
		t.Errorf("expected INSUFFICIENT_DATA for source-abstain alone, got %s (decay %.2f)", r.Verdict, r.DecayScore)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("expected decay 0.00 (source abstain), got %.2f", r.DecayScore)
	}
	if !r.SourceAbstain {
		t.Error("expected SourceAbstain=true")
	}
	if r.FieldAbstain {
		t.Error("expected FieldAbstain=false")
	}
}

func TestHealthyInvariant(t *testing.T) {
	// Invariant: a row may never report HEALTHY with a non-trivial DecayScore.
	// Both gates at 0.85 (just below HealthyThreshold of 0.8... wait,
	// HealthyThreshold is 0.8).  0.85 is above 0.8, so should be HEALTHY
	// with decay = 1 - 0.85*0.85 ≈ 0.2775 → that decays above MaxHealthyDecay.
	// Actually, if both are >= 0.8, they're both "healthy contribution".
	// But decay = 1 - 0.85*0.85 = 0.2775 which exceeds MaxHealthyDecay of 0.05.
	// The invariant should bump it to DEGRADED.
	fp := 0.85
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "Image",
		Liveness:              "active",
		Volume:                85,
		BaselineVolume:        100,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict == VHealthy {
		t.Errorf("decay %.2f > MaxHealthyDecay %.2f — must not be HEALTHY",
			r.DecayScore, MaxHealthyDecay)
	}
	// With both gates above HealthyThreshold (0.8), it should be at most DEGRADED.
	if r.Verdict == VDeadSource || r.Verdict == VDeadField {
		t.Errorf("both gates above HealthyThreshold — expected DEGRADED, not %s", r.Verdict)
	}
}

func TestFieldNameInReason(t *testing.T) {
	// Priority 2: field name must appear in reason, not hardcoded "Image".
	fp := 0.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "CommandLine",
		Liveness:              "active",
		Volume:                100,
		BaselineVolume:        100,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VDeadField {
		t.Fatalf("expected DEAD:FIELD, got %s", r.Verdict)
	}
	// Should contain the actual field name, not "Image".
	if got := r.Reason; !strings.Contains(got, "CommandLine") {
		t.Errorf("reason %q should contain field name 'CommandLine'", got)
	}
}

func TestFieldNameFallback(t *testing.T) {
	// When Field is empty, use neutral "field".
	fp := 0.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "",
		Liveness:              "active",
		Volume:                100,
		BaselineVolume:        100,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VDeadField {
		t.Fatalf("expected DEAD:FIELD, got %s", r.Verdict)
	}
	if got := r.Reason; !strings.Contains(got, "field populate") {
		t.Errorf("reason %q should contain fallback 'field'", got)
	}
}

func TestLivenessCaseInsensitive(t *testing.T) {
	fp := 1.0
	ev := Evidence{
		Rule:                  "r.yml",
		Field:                 "Image",
		Liveness:              "Active",
		Volume:                64,
		BaselineVolume:        64,
		FieldPopulate:         &fp,
		BaselineFieldPopulate: 1.0,
	}
	r := Score(ev)
	if r.Verdict != VHealthy {
		t.Errorf("expected HEALTHY for liveness 'Active', got %s", r.Verdict)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("expected decay 0.00, got %.2f", r.DecayScore)
	}
}

func TestScoreAllEmpty(t *testing.T) {
	results := ScoreAll([]Evidence{})
	if len(results) != 0 {
		t.Errorf("expected empty slice, got %d results", len(results))
	}
}

// ---------- helpers ----------

func fp(v float64) *float64 { return &v }

// assertReconciles is the explanation-integrity harness. A gate's stated value
// must equal the product of the contributions its explanation lists, and the
// health must equal the product of the gates — otherwise the breakdown shown to
// an operator describes a number the scorer did not actually produce.
func assertReconciles(t *testing.T, label string, r Result) {
	t.Helper()
	const eps = 1e-9

	health := 1.0
	for _, g := range r.Gates {
		if want := g.product(); math.Abs(g.Value-want) > eps {
			t.Errorf("%s: gate %q value %.4f but its factors multiply to %.4f — breakdown does not reconcile",
				label, g.Name, g.Value, want)
		}
		if len(g.Factors) == 0 {
			t.Errorf("%s: gate %q has no contributing factors to explain its value", label, g.Name)
		}
		health *= g.Value
	}
	if math.Abs(r.Health-health) > eps {
		t.Errorf("%s: health %.4f but gates multiply to %.4f", label, r.Health, health)
	}
	if math.Abs(r.DecayScore-(1-r.Health)) > eps {
		t.Errorf("%s: decay %.4f != 1-health %.4f", label, r.DecayScore, 1-r.Health)
	}
	if r.Reason == "" {
		t.Errorf("%s: verdict %s carries no reason", label, r.Verdict)
	}
}

// ---------- reconciliation ----------

func TestExplanationReconcilesAcrossAllPaths(t *testing.T) {
	cases := map[string]Evidence{
		"healthy":         {Rule: "r", Liveness: "active", Volume: 64, BaselineVolume: 64, FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0},
		"dead source":     {Rule: "r", Liveness: "active", Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0},
		"dead field":      {Rule: "r", Liveness: "active", Volume: 234, BaselineVolume: 64, FieldPopulate: fp(0.0), BaselineFieldPopulate: 1.0},
		"degraded both":   {Rule: "r", Liveness: "active", Volume: 32, BaselineVolume: 64, FieldPopulate: fp(0.5), BaselineFieldPopulate: 1.0},
		"disconnected":    {Rule: "r", Liveness: "disconnected", Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0},
		"no baseline":     {Rule: "r", Liveness: "active", Volume: 0, BaselineVolume: 0, FieldPopulate: nil, BaselineFieldPopulate: 0},
		"over collection": {Rule: "r", Liveness: "active", Volume: 5000, BaselineVolume: 64, FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0},
		"compound":        {Rule: "r", Liveness: "active", Volume: 58, BaselineVolume: 64, FieldPopulate: fp(0.9), BaselineFieldPopulate: 1.0},
	}
	for label, ev := range cases {
		assertReconciles(t, label, Score(ev))
	}
}

func TestExplanationRestatesArithmetic(t *testing.T) {
	r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 22, BaselineVolume: 200,
		FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})

	// The final line must let a reader recompute the score by hand.
	for _, want := range []string{"DecayScore: 1 - (", " × ", "0.11", "→ DEAD:SOURCE"} {
		if !strings.Contains(r.Explanation, want) {
			t.Errorf("explanation missing %q:\n%s", want, r.Explanation)
		}
	}
	// And every gate must be named with its own factors.
	for _, gate := range []string{"P(source):", "P(field):", "P(behavior):"} {
		if !strings.Contains(r.Explanation, gate) {
			t.Errorf("explanation missing %q:\n%s", gate, r.Explanation)
		}
	}
}

// ---------- band boundaries ----------

func TestBandBoundariesAreExact(t *testing.T) {
	// DeadThreshold is exclusive: exactly 0.20 of baseline is DEGRADED, not dead.
	cases := []struct {
		name           string
		volume         int
		wantDeadSource bool
	}{
		{"just above dead", 20, false}, // 0.20 exactly
		{"just below dead", 19, true},  // 0.19
	}
	for _, c := range cases {
		r := Score(Evidence{Rule: "r", Liveness: "active", Volume: c.volume, BaselineVolume: 100,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
		if got := r.Verdict == VDeadSource; got != c.wantDeadSource {
			t.Errorf("%s (volume %d/100): verdict %s, wantDeadSource=%v",
				c.name, c.volume, r.Verdict, c.wantDeadSource)
		}
	}

	// Same exclusivity on the field gate.
	if r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 100, BaselineVolume: 100,
		FieldPopulate: fp(0.20), BaselineFieldPopulate: 1.0}); r.Verdict == VDeadField {
		t.Errorf("field at exactly DeadThreshold should not be DEAD:FIELD, got %s", r.Verdict)
	}
	if r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 100, BaselineVolume: 100,
		FieldPopulate: fp(0.19), BaselineFieldPopulate: 1.0}); r.Verdict != VDeadField {
		t.Errorf("field just below DeadThreshold should be DEAD:FIELD, got %s", r.Verdict)
	}
}

// TestVerdictMonotonicInVolume is the property that catches band-table errors:
// as the source measurement worsens, the verdict must never improve.
func TestVerdictMonotonicInVolume(t *testing.T) {
	rank := map[string]int{VHealthy: 0, VDegraded: 1, VDeadField: 2, VDeadSource: 3}
	prev, prevVol := -1, 0
	for vol := 100; vol >= 0; vol-- {
		r := Score(Evidence{Rule: "r", Liveness: "active", Volume: vol, BaselineVolume: 100,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
		got, ok := rank[r.Verdict]
		if !ok {
			t.Fatalf("volume %d: unranked verdict %s", vol, r.Verdict)
		}
		if got < prev {
			t.Fatalf("verdict improved as volume fell: %d events → rank %d, %d events → rank %d (%s)",
				prevVol, prev, vol, got, r.Verdict)
		}
		prev, prevVol = got, vol
	}
}

// ---------- over-collection ----------

func TestOverCollectionIsDegradedNotHealthy(t *testing.T) {
	// 2000 events against a baseline of 64 is a lost filter or a duplicated
	// pipeline. Clamping the ratio to 1.0 used to score this a perfect 0.00.
	r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 2000, BaselineVolume: 64,
		FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
	if r.Verdict != VDegraded {
		t.Errorf("expected DEGRADED for 3125%% of baseline, got %s (decay %.2f)", r.Verdict, r.DecayScore)
	}
	if !strings.Contains(r.Reason, "over-collection") {
		t.Errorf("reason should name over-collection, got %q", r.Reason)
	}
}

func TestOverCollectionNeverReadsAsDead(t *testing.T) {
	// Events are demonstrably flowing, so no amount of flooding may report the
	// source dead — that would send an operator hunting a non-existent outage.
	for _, vol := range []int{200, 2000, 200000, 20000000} {
		r := Score(Evidence{Rule: "r", Liveness: "active", Volume: vol, BaselineVolume: 64,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
		if r.Verdict == VDeadSource {
			t.Errorf("volume %d: over-collection reported DEAD:SOURCE", vol)
		}
		if r.PSource < DeadThreshold {
			t.Errorf("volume %d: P(source) %.2f fell below the over-collection floor %.2f",
				vol, r.PSource, DeadThreshold)
		}
	}
}

func TestNormalVarianceStaysHealthy(t *testing.T) {
	// Up to OverThreshold, above-baseline volume is ordinary variance.
	for _, vol := range []int{64, 96, 128, 192} {
		r := Score(Evidence{Rule: "r", Liveness: "active", Volume: vol, BaselineVolume: 64,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
		if r.Verdict != VHealthy {
			t.Errorf("volume %d/64 (%.1fx) should be HEALTHY, got %s", vol, float64(vol)/64, r.Verdict)
		}
	}
}

// ---------- probe failure ----------

func TestProbeErrorIsNotADetectionOutage(t *testing.T) {
	// Volume 0 against a baseline of 64 is textbook DEAD:SOURCE — but the probe
	// failed, so the zero is an artefact of the measurement, not the telemetry.
	r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 0, BaselineVolume: 64,
		FieldPopulate: nil, BaselineFieldPopulate: 1.0,
		ProbeError: "dial tcp 127.0.0.1:9200: connection refused"})

	if r.Verdict != VProbeError {
		t.Fatalf("expected PROBE_ERROR, got %s", r.Verdict)
	}
	if r.DecayScore != 0.0 {
		t.Errorf("a failed probe must not claim decay, got %.2f", r.DecayScore)
	}
	if !strings.Contains(r.Reason, "connection refused") {
		t.Errorf("reason should carry the probe error, got %q", r.Reason)
	}
	assertReconciles(t, "probe error", r)
}

// ---------- the healthy ceiling ----------

func TestHealthyCeilingPreservesGateDetail(t *testing.T) {
	// Both gates sit above HealthyThreshold but compound past MaxHealthyDecay.
	// The ceiling must explain *which* gates slipped; it used to replace the
	// per-gate detail with a bare threshold message.
	r := Score(Evidence{Rule: "r", Liveness: "active", Volume: 58, BaselineVolume: 64,
		FieldPopulate: fp(0.9), BaselineFieldPopulate: 1.0, Field: "image"})

	if r.Verdict != VDegraded {
		t.Fatalf("expected DEGRADED from the ceiling, got %s (decay %.2f)", r.Verdict, r.DecayScore)
	}
	for _, want := range []string{"volume 58", "image populate", "exceeds healthy ceiling"} {
		if !strings.Contains(r.Reason, want) {
			t.Errorf("ceiling reason lost detail %q, got %q", want, r.Reason)
		}
	}
}

func TestNoHealthyVerdictAboveCeiling(t *testing.T) {
	// The invariant, swept rather than spot-checked.
	for v := 0; v <= 100; v++ {
		r := Score(Evidence{Rule: "r", Liveness: "active", Volume: v, BaselineVolume: 100,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0})
		if r.Verdict == VHealthy && r.DecayScore > MaxHealthyDecay {
			t.Fatalf("volume %d: HEALTHY with decay %.2f above ceiling %.2f", v, r.DecayScore, MaxHealthyDecay)
		}
	}
}
