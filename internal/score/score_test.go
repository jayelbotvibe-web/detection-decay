package score

import "testing"

func TestInsufficientData(t *testing.T) {
	fp := 1.0 // non-null, healthy
	ev := Evidence{
		Liveness:             "active",
		Volume:               100,
		BaselineVolume:       100,
		FieldPopulate:        nil, // null → field data missing
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
		Liveness:             "active",
		Volume:               64,
		BaselineVolume:       64,
		FieldPopulate:        &fp,
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
		Liveness:             "active",
		Volume:               0,
		BaselineVolume:       64,
		FieldPopulate:        &fp,
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

func TestProbeError(t *testing.T) {
	ev := Evidence{
		Liveness:              "",
		Volume:                0,
		BaselineVolume:        64,
		FieldPopulate:         nil,
		BaselineFieldPopulate: 1.0,
		ProbeError:            "indexer unreachable",
	}
	r := Score(ev)
	if r.Verdict != VProbeError {
		t.Errorf("expected PROBE_ERROR for failed measurement, got %s", r.Verdict)
	}
	if r.Verdict == VDeadSource {
		t.Error("PROBE_ERROR must NOT be classified as DEAD:SOURCE")
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
