package score

import "testing"

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
	if got := r.Reason; !contains(got, "CommandLine") {
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
	if got := r.Reason; !contains(got, "field populate") {
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

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
