package score

import "testing"

func TestInsufficientData(t *testing.T) {
	fp := 1.0 // non-null, healthy
	ev := Evidence{
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

func TestLivenessCaseInsensitive(t *testing.T) {
	fp := 1.0
	ev := Evidence{
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
