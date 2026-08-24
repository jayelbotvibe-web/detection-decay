package calibrate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

var now = time.Date(2026, 8, 24, 16, 45, 0, 0, time.UTC)

func fp(v float64) *float64 { return &v }

// run builds a run artifact from evidence rows, scored the way the tool would.
func run(t *testing.T, evs ...score.Evidence) []byte {
	t.Helper()
	data, err := json.Marshal(struct {
		Results []score.Result `json:"results"`
	}{score.ScoreAll(evs)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func healthy(rule string, volume int) score.Evidence {
	return score.Evidence{Rule: rule, State: "live", Liveness: "active",
		Volume: volume, BaselineVolume: 3000, FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0}
}

func TestDeriveUsesMedian(t *testing.T) {
	// Median, not mean: one outlier run must not move the baseline, and outliers
	// are exactly what a decaying pipeline produces.
	var runs [][]byte
	for _, v := range []int{2900, 3000, 3100, 2950, 3050} {
		runs = append(runs, run(t, healthy("r.yml", v)))
	}
	f, _ := Derive(runs, 30, 3, now)

	b, ok := f.Baselines[Key("r.yml", "live")]
	if !ok {
		t.Fatalf("no baseline derived: %+v", f.Baselines)
	}
	if b.Volume != 3000 {
		t.Errorf("volume = %d, want the median 3000", b.Volume)
	}
	if b.Samples != 5 {
		t.Errorf("samples = %d, want 5", b.Samples)
	}
}

// TestRatchetGuard is the load-bearing test of this package.
//
// A rolling baseline computed from every observation follows a dead source
// down: within a few runs the baseline reaches zero and a total outage reports
// perfectly healthy. That failure is silent and permanent, which makes it worse
// than having no calibration at all.
func TestRatchetGuard(t *testing.T) {
	var runs [][]byte
	for i := 0; i < 5; i++ {
		runs = append(runs, run(t, healthy("r.yml", 3000)))
	}
	// The source dies and stays dead, for far longer than it was ever healthy.
	for i := 0; i < 50; i++ {
		runs = append(runs, run(t, score.Evidence{
			Rule: "r.yml", State: "live", Liveness: "active",
			Volume: 0, BaselineVolume: 3000, FieldPopulate: nil, BaselineFieldPopulate: 1.0,
		}))
	}

	f, _ := Derive(runs, 100, 3, now)
	b, ok := f.Baselines[Key("r.yml", "live")]
	if !ok {
		t.Fatal("baseline disappeared entirely once the source died")
	}
	if b.Volume != 3000 {
		t.Fatalf("baseline ratcheted to %d — a dead source calibrated its own outage away", b.Volume)
	}
	if b.Samples != 5 {
		t.Errorf("samples = %d, want only the 5 healthy observations", b.Samples)
	}
}

func TestDegradedObservationsDoNotContribute(t *testing.T) {
	// Only HEALTHY describes what normal looks like. A DEGRADED observation is
	// already decay, and folding it in normalises the decay.
	runs := [][]byte{
		run(t, healthy("r.yml", 3000)),
		run(t, healthy("r.yml", 3000)),
		run(t, healthy("r.yml", 3000)),
		run(t, score.Evidence{Rule: "r.yml", State: "live", Liveness: "active",
			Volume: 1500, BaselineVolume: 3000, FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0}),
	}
	f, _ := Derive(runs, 30, 3, now)
	if b := f.Baselines[Key("r.yml", "live")]; b.Samples != 3 || b.Volume != 3000 {
		t.Errorf("degraded observation contributed: %+v", b)
	}
}

func TestMinSamplesOmitsThinBaselines(t *testing.T) {
	// A baseline derived from one observation is just that observation.
	runs := [][]byte{run(t, healthy("r.yml", 3000)), run(t, healthy("r.yml", 3000))}

	f, warnings := Derive(runs, 30, 3, now)
	if len(f.Baselines) != 0 {
		t.Errorf("published a baseline from %d samples with min-samples 3", 2)
	}
	if len(warnings) == 0 {
		t.Error("omitting every baseline should warn")
	}

	f, _ = Derive(runs, 30, 2, now)
	if len(f.Baselines) != 1 {
		t.Errorf("min-samples 2 should publish, got %d baselines", len(f.Baselines))
	}
}

func TestWindowBoundsRecency(t *testing.T) {
	var runs [][]byte
	for i := 0; i < 10; i++ {
		runs = append(runs, run(t, healthy("r.yml", 1000))) // old volume
	}
	for i := 0; i < 5; i++ {
		runs = append(runs, run(t, healthy("r.yml", 3000))) // current volume
	}
	f, _ := Derive(runs, 5, 3, now)
	if b := f.Baselines[Key("r.yml", "live")]; b.Volume != 3000 {
		t.Errorf("window ignored: volume = %d, want 3000 from the last 5 runs", b.Volume)
	}
}

func TestNoHealthyObservationsWarnsClearly(t *testing.T) {
	runs := [][]byte{run(t, score.Evidence{Rule: "r.yml", State: "live", Liveness: "active",
		Volume: 0, BaselineVolume: 3000, FieldPopulate: nil, BaselineFieldPopulate: 1.0})}

	f, warnings := Derive(runs, 30, 1, now)
	if len(f.Baselines) != 0 {
		t.Error("derived a baseline with no healthy observation to derive it from")
	}
	found := false
	for _, w := range warnings {
		if len(w) > 0 && contains(w, "no healthy state") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings should explain there was no healthy state: %v", warnings)
	}
}

func TestCorruptRunIsSkippedNotFatal(t *testing.T) {
	runs := [][]byte{
		run(t, healthy("r.yml", 3000)),
		[]byte("{ not json"),
		run(t, healthy("r.yml", 3000)),
		run(t, healthy("r.yml", 3000)),
	}
	f, warnings := Derive(runs, 30, 3, now)
	if len(f.Baselines) != 1 {
		t.Errorf("a corrupt run should be skipped, not abort calibration: %+v", f.Baselines)
	}
	if len(warnings) == 0 {
		t.Error("skipping a run should warn")
	}
}

// ---------- Apply ----------

func TestApplyRespectsExplicitBaseline(t *testing.T) {
	// A derived number is a convenience. Silently overriding a figure an
	// operator wrote by hand would make the score untraceable to its input.
	f := File{GeneratedAt: now.Format(time.RFC3339),
		Baselines: map[string]Baseline{Key("r.yml", "live"): {Volume: 3000, FieldPopulate: 1.0}}}

	out, _ := Apply([]score.Evidence{{Rule: "r.yml", State: "live", Liveness: "active",
		Volume: 100, BaselineVolume: 64, BaselineFieldPopulate: 0.9}}, f, now)

	if out[0].BaselineVolume != 64 {
		t.Errorf("overrode an explicit baseline: %d", out[0].BaselineVolume)
	}
	if out[0].BaselineFieldPopulate != 0.9 {
		t.Errorf("overrode an explicit field baseline: %v", out[0].BaselineFieldPopulate)
	}
}

func TestApplyFillsMissingAndSetsAge(t *testing.T) {
	// 60 days, comfortably past score.StaleBaselineSeconds, so the age is
	// observable in the confidence gate rather than merely stored.
	generated := now.Add(-60 * 24 * time.Hour)
	f := File{GeneratedAt: generated.Format(time.RFC3339),
		Baselines: map[string]Baseline{Key("r.yml", "live"): {Volume: 3000, FieldPopulate: 1.0}}}

	out, warnings := Apply([]score.Evidence{
		{Rule: "r.yml", State: "live", Liveness: "active", Volume: 2900, FieldPopulate: fp(1.0)},
		{Rule: "unknown.yml", State: "live", Liveness: "active", Volume: 5},
	}, f, now)

	if out[0].BaselineVolume != 3000 || out[0].BaselineFieldPopulate != 1.0 {
		t.Errorf("did not fill the missing baseline: %+v", out[0])
	}
	if want := 60 * 24 * 3600; out[0].BaselineAgeSeconds != want {
		t.Errorf("age = %d, want %d — staleness must reach the confidence gate",
			out[0].BaselineAgeSeconds, want)
	}
	if out[1].BaselineVolume != 0 {
		t.Errorf("invented a baseline for an unknown rule: %+v", out[1])
	}
	if len(warnings) == 0 {
		t.Error("a row with no derivable baseline should warn")
	}

	// The filled row must now score, and its age must lower confidence.
	r := score.Score(out[0])
	if r.Verdict == score.VInsufficientData {
		t.Errorf("filled row still reports INSUFFICIENT_DATA: %s", r.Reason)
	}
	if r.ConfidenceScore >= 1.0 {
		t.Errorf("a 60-day-old baseline should not score full confidence: %.2f", r.ConfidenceScore)
	}
}

// TestApplyFillsBaselinesNotMeasurements: calibration supplies what normal looks
// like, never what was observed. A row with no field measurement still abstains
// on the field gate, because nothing measured it.
func TestApplyFillsBaselinesNotMeasurements(t *testing.T) {
	f := File{GeneratedAt: now.Format(time.RFC3339),
		Baselines: map[string]Baseline{Key("r.yml", "live"): {Volume: 3000, FieldPopulate: 1.0}}}

	out, _ := Apply([]score.Evidence{
		{Rule: "r.yml", State: "live", Liveness: "active", Volume: 2900},
	}, f, now)

	if out[0].FieldPopulate != nil {
		t.Fatal("Apply invented a field measurement")
	}
	if r := score.Score(out[0]); r.Verdict != score.VInsufficientData {
		t.Errorf("an unmeasured field must still abstain, got %s", r.Verdict)
	}
}

func TestApplyDoesNotMutateInput(t *testing.T) {
	f := File{GeneratedAt: now.Format(time.RFC3339),
		Baselines: map[string]Baseline{Key("r.yml", "live"): {Volume: 3000}}}
	in := []score.Evidence{{Rule: "r.yml", State: "live", Liveness: "active", Volume: 2900}}

	Apply(in, f, now)
	if in[0].BaselineVolume != 0 {
		t.Error("Apply mutated the caller's slice")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
