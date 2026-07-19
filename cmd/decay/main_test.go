package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

func TestRenderHTMLEmpty(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("renderHTML panicked on empty results: %v", rec)
		}
	}()
	out := renderHTML("test.json", []score.Result{})
	if !strings.Contains(out, "no evidence rows") {
		t.Errorf("expected empty-state message in HTML output")
	}
	if !strings.Contains(out, "test.json") {
		t.Errorf("expected evidence path in HTML output")
	}
}

func TestRenderTextEmpty(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("renderText panicked on empty results: %v", rec)
		}
	}()
	out := renderText("test.json", []score.Result{})
	if !strings.Contains(out, "no evidence rows") {
		t.Errorf("expected empty-state message in text output")
	}
}

func TestRenderHTMLReportsEvidencePath(t *testing.T) {
	fp := 1.0
	res := score.ScoreAll([]score.Evidence{{
		Rule: "r.yml", State: "baseline", Liveness: "active",
		Volume: 10, BaselineVolume: 10,
		FieldPopulate: &fp, BaselineFieldPopulate: 1.0,
	}})
	out := renderHTML("lab-evidence.json", res)
	if !strings.Contains(out, "lab-evidence.json") {
		t.Errorf("expected evidence path in hero, hardcoded label regression?")
	}
	if strings.Contains(out, "purple-loop Windows Sysmon baseline") {
		t.Errorf("hardcoded lab label still present")
	}
}

func TestRendererAgreement(t *testing.T) {
	// Both renderers must agree on the summary tally for a fixture
	// covering every verdict including DEGRADED.
	fpH := 1.0
	fpD := 0.5
	fpF := 0.0
	evs := []score.Evidence{
		{Rule: "healthy.yml", State: "ok", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fpH, BaselineFieldPopulate: 1.0, Field: "Image"},
		{Rule: "degraded.yml", State: "low", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fpD, BaselineFieldPopulate: 1.0, Field: "Image"},
		{Rule: "dead_field.yml", State: "null", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fpF, BaselineFieldPopulate: 1.0, Field: "Image"},
		{Rule: "dead_source.yml", State: "gone", Liveness: "active",
			Volume: 0, BaselineVolume: 100,
			FieldPopulate: &fpH, BaselineFieldPopulate: 1.0, Field: "Image"},
		{Rule: "insuff.yml", State: "new", Liveness: "active",
			Volume: 0, BaselineVolume: 0,
			FieldPopulate: nil, BaselineFieldPopulate: 1.0},
	}
	results := score.ScoreAll(evs)

	textOut := renderText("test.json", results)
	htmlOut := renderHTML("test.json", results)

	s := tally(results)
	if s.evaluated != 5 {
		t.Errorf("expected 5 evaluated, got %d", s.evaluated)
	}
	if s.healthy != 1 {
		t.Errorf("expected 1 healthy, got %d", s.healthy)
	}
	if s.silent != 3 { // degraded + dead_field + dead_source
		t.Errorf("expected 3 silent, got %d", s.silent)
	}

	// Both renderers must agree on the silent count.
	silentStr := "3 silently decayed"
	if !strings.Contains(textOut, silentStr) {
		t.Errorf("text missing %q", silentStr)
	}
	if !strings.Contains(htmlOut, silentStr) {
		t.Errorf("html missing %q", silentStr)
	}

	// Both must agree on evaluated count.
	evalStr := "5 evaluated"
	if !strings.Contains(textOut, evalStr) {
		t.Errorf("text missing %q", evalStr)
	}
	if !strings.Contains(htmlOut, evalStr) {
		t.Errorf("html missing %q", evalStr)
	}

	// Both must show the DEGRADED verdict.
	if !strings.Contains(textOut, string(score.VDegraded)) {
		t.Errorf("text missing DEGRADED verdict")
	}
	if !strings.Contains(htmlOut, string(score.VDegraded)) {
		t.Errorf("html missing DEGRADED verdict")
	}
}

func TestHTMLEscaping(t *testing.T) {
	// Priority 4: all user-controlled fields must be escaped.
	// Use DEAD:FIELD for the field-name-in-reason path, and
	// disconnected liveness for the liveness-in-hero path.
	fpZ := 0.0
	evs := []score.Evidence{
		{
			// DEAD:FIELD — field name appears in reason output.
			Rule:                  "<script>alert(1)</script>",
			State:                 "<img onerror=alert(1)>",
			Liveness:              "active",
			Volume:                200,
			BaselineVolume:        200,
			FieldPopulate:         &fpZ,
			BaselineFieldPopulate: 1.0,
			Field:                 "<b>Image</b>",
		},
		{
			// Disconnected — liveness appears in output.
			Rule:                  "also_bad.yml",
			State:                 "x",
			Liveness:              "disconnected<script>",
			Volume:                0,
			BaselineVolume:        100,
			FieldPopulate:         nil,
			BaselineFieldPopulate: 1.0,
			Field:                 "",
		},
	}
	results := score.ScoreAll(evs)
	out := renderHTML("test.json", results)

	// Raw script/HTML tags must not appear.
	for _, payload := range []string{
		"<script>alert(1)</script>",
		"<img onerror=alert(1)>",
		"<b>Image</b>",
		"disconnected<script>",
	} {
		if strings.Contains(out, payload) {
			t.Errorf("HTML output contains unescaped payload: %q", payload)
		}
	}

	// Escaped equivalents must appear where the values are rendered.
	checks := map[string]string{
		"rule":     "&lt;script&gt;alert(1)&lt;/script&gt;",
		"state":    "&lt;img onerror=alert(1)&gt;",
		"field":    "&lt;b&gt;Image&lt;/b&gt;",
		"liveness": "disconnected&lt;script&gt;",
	}
	for label, escaped := range checks {
		if !strings.Contains(out, escaped) {
			t.Errorf("HTML output missing escaped %s: %q (out snippet: %s)",
				label, escaped, out[max(0, len(out)-800):])
		}
	}
}

func TestINSUFFICIENT_DATAHeroClass(t *testing.T) {
	// INSUFFICIENT_DATA should not render with the green .healthy class.
	evs := []score.Evidence{{
		Rule: "new.yml", State: "first", Liveness: "active",
		Volume: 0, BaselineVolume: 0,
		FieldPopulate: nil, BaselineFieldPopulate: 1.0,
	}}
	results := score.ScoreAll(evs)
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}
	if results[0].Verdict != score.VInsufficientData {
		t.Fatalf("expected INSUFFICIENT_DATA, got %s", results[0].Verdict)
	}

	out := renderHTML("test.json", results)

	// The worst-verdict div must NOT use the healthy class.
	if strings.Contains(out, `class="worst healthy"`) {
		t.Errorf("INSUFFICIENT_DATA hero rendered with healthy class — should be gray")
	}
	// It should use gray.
	if !strings.Contains(out, `class="worst gray"`) {
		t.Errorf("INSUFFICIENT_DATA hero missing gray class")
	}
}

func TestSortStable(t *testing.T) {
	// Stable sort: tie on decay score → rule name tiebreak.
	fp := 1.0
	evs := []score.Evidence{
		{Rule: "z.yml", State: "a", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fp, BaselineFieldPopulate: 1.0},
		{Rule: "a.yml", State: "b", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fp, BaselineFieldPopulate: 1.0},
		{Rule: "m.yml", State: "c", Liveness: "active",
			Volume: 100, BaselineVolume: 100,
			FieldPopulate: &fp, BaselineFieldPopulate: 1.0},
	}
	results := score.ScoreAll(evs)
	// Apply the same sort as main().
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].DecayScore != results[j].DecayScore {
			return results[i].DecayScore > results[j].DecayScore
		}
		return results[i].Rule < results[j].Rule
	})
	// Results should be in rule-name order (all decay = 0.0).
	if results[0].Rule != "a.yml" {
		t.Errorf("expected a.yml first, got %s", results[0].Rule)
	}
	if results[1].Rule != "m.yml" {
		t.Errorf("expected m.yml second, got %s", results[1].Rule)
	}
	if results[2].Rule != "z.yml" {
		t.Errorf("expected z.yml third, got %s", results[2].Rule)
	}
}
