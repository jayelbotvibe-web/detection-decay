package score

import (
	"strings"
	"testing"
)

// TestValidateCatchesSilentFalseAlarms pins the two inputs that used to produce
// a confident, wrong DEAD:SOURCE rather than an error.
func TestValidateCatchesSilentFalseAlarms(t *testing.T) {
	// An omitted liveness decoded as "", failed the active check, and reported
	// "agent disconnected" for a row that never mentioned an agent.
	errs := Validate([]Evidence{{Rule: "r.yml", Volume: 64, BaselineVolume: 64,
		FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0}})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for missing liveness, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "liveness") {
		t.Errorf("error should name the liveness key, got %q", errs[0])
	}

	// Confirm the scorer would otherwise have produced the false alarm, so this
	// test documents the behaviour it is preventing.
	if r := Score(Evidence{Rule: "r.yml", Volume: 64, BaselineVolume: 64,
		FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0}); r.Verdict != VDeadSource {
		t.Errorf("precondition changed: unvalidated missing liveness now yields %s", r.Verdict)
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	f := 95.0 // a percentage where a rate belongs
	errs := Validate([]Evidence{
		{Rule: "a.yml", Liveness: "active", Volume: -5, BaselineVolume: 64,
			FieldPopulate: &f, BaselineFieldPopulate: 1.0},
		{Rule: "", Liveness: "active", Volume: 1, BaselineVolume: 64,
			FieldPopulate: fp(0.5), BaselineFieldPopulate: 4.0},
	})
	// A collector emitting a malformed file repeats the mistake on every row,
	// so all problems are reported at once rather than one run at a time.
	if len(errs) != 4 {
		t.Fatalf("expected 4 errors, got %d: %v", len(errs), errs)
	}
	joined := ""
	for _, e := range errs {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{"volume", "field_populate", "rule", "baseline_field_populate", "a.yml", "row 1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors missing %q:\n%s", want, joined)
		}
	}
}

func TestValidateSkipsMeasurementsOfAFailedProbe(t *testing.T) {
	// A failed probe measured nothing, so its zeroed fields are not errors.
	errs := Validate([]Evidence{{Rule: "r.yml", ProbeError: "connection refused"}})
	if len(errs) != 0 {
		t.Errorf("a probe-error row should not be validated for measurements: %v", errs)
	}
}

func TestValidateAcceptsGoodEvidence(t *testing.T) {
	if errs := Validate([]Evidence{
		{Rule: "r.yml", State: "baseline", Liveness: "active", Volume: 64, BaselineVolume: 64,
			FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0, Field: "image"},
		{Rule: "r.yml", State: "death", Liveness: "active", Volume: 0, BaselineVolume: 64,
			FieldPopulate: nil, BaselineFieldPopulate: 1.0, Field: "image"},
	}); len(errs) != 0 {
		t.Errorf("valid evidence rejected: %v", errs)
	}
}

// ---------- confidence ----------

// TestConfidenceIsOrthogonalToVerdict: the same finding, measured well and
// measured badly, must reach the same verdict with different confidence.
func TestConfidenceIsOrthogonalToVerdict(t *testing.T) {
	solid := Score(Evidence{Rule: "r", Liveness: "active", Volume: 3000, BaselineVolume: 3000,
		FieldPopulate: fp(0.0), BaselineFieldPopulate: 1.0, Field: "image"})
	thin := Score(Evidence{Rule: "r", Liveness: "active", Volume: 4, BaselineVolume: 4,
		FieldPopulate: fp(0.0), BaselineFieldPopulate: 1.0, Field: "image"})

	if solid.Verdict != VDeadField || thin.Verdict != VDeadField {
		t.Fatalf("expected both DEAD:FIELD, got %s and %s", solid.Verdict, thin.Verdict)
	}
	if solid.DecayScore != thin.DecayScore {
		t.Errorf("confidence leaked into the score: %.2f vs %.2f", solid.DecayScore, thin.DecayScore)
	}
	if !(solid.ConfidenceScore > thin.ConfidenceScore) {
		t.Errorf("a 3000-event baseline should outrank a 4-event one: %.2f vs %.2f",
			solid.ConfidenceScore, thin.ConfidenceScore)
	}
	if solid.ConfidenceLabel != CHigh {
		t.Errorf("solid sample should be HIGH confidence, got %s", solid.ConfidenceLabel)
	}
}

func TestStaleBaselineLowersConfidence(t *testing.T) {
	fresh := Score(Evidence{Rule: "r", Liveness: "active", Volume: 3000, BaselineVolume: 3000,
		FieldPopulate: fp(0.0), BaselineFieldPopulate: 1.0})
	stale := Score(Evidence{Rule: "r", Liveness: "active", Volume: 3000, BaselineVolume: 3000,
		FieldPopulate: fp(0.0), BaselineFieldPopulate: 1.0, BaselineAgeSeconds: 60 * 86400})

	if !(stale.ConfidenceScore < fresh.ConfidenceScore) {
		t.Errorf("a 60-day-old baseline should reduce confidence: %.2f vs %.2f",
			stale.ConfidenceScore, fresh.ConfidenceScore)
	}
	if stale.DecayScore != fresh.DecayScore {
		t.Errorf("baseline age must not move the score: %.2f vs %.2f", stale.DecayScore, fresh.DecayScore)
	}
}

func TestConfidenceReconciles(t *testing.T) {
	for _, ev := range []Evidence{
		{Rule: "r", Liveness: "active", Volume: 64, BaselineVolume: 64, FieldPopulate: fp(1.0), BaselineFieldPopulate: 1.0},
		{Rule: "r", Liveness: "active", Volume: 2, BaselineVolume: 4, FieldPopulate: nil, BaselineFieldPopulate: 1.0},
		{Rule: "r", Liveness: "active", Volume: 0, BaselineVolume: 0, FieldPopulate: nil, BaselineFieldPopulate: 0, BaselineAgeSeconds: 90 * 86400},
	} {
		r := Score(ev)
		if got, want := r.Confidence.Value, r.Confidence.product(); got != want {
			t.Errorf("confidence %.4f but factors multiply to %.4f", got, want)
		}
		if r.ConfidenceLabel == "" {
			t.Error("confidence has no label")
		}
	}
}

func TestFailedProbeHasNoConfidence(t *testing.T) {
	r := Score(Evidence{Rule: "r", ProbeError: "connection refused"})
	if r.ConfidenceLabel != CLow || r.ConfidenceScore != 0 {
		t.Errorf("a failed probe measured nothing and cannot be confident: %s %.2f",
			r.ConfidenceLabel, r.ConfidenceScore)
	}
}
