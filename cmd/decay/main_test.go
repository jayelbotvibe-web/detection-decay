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

// ---------- display regressions ----------

// stripANSI removes SGR escape sequences so tests can measure visible width.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func fpv(v float64) *float64 { return &v }

// TestEveryVerdictIsStyled is the property that would have caught the silent
// styling gaps: a verdict with no colour renders as plain text and a verdict
// with no CSS class renders unstyled in the dashboard.
func TestEveryVerdictIsStyled(t *testing.T) {
	verdicts := []string{
		score.VHealthy, score.VDegraded, score.VDeadSource,
		score.VDeadField, score.VInsufficientData, score.VProbeError,
	}
	for _, v := range verdicts {
		c := verdictColor(v)
		if got := colour("x", c); got == "x" {
			t.Errorf("verdict %s maps to colour %q which is not in the colour map — renders uncoloured", v, c)
		}
		if verdictCSS(v) == "" {
			t.Errorf("verdict %s has no CSS class", v)
		}
	}
}

// TestFieldBadgesAreColourable guards the specific bug: fieldDisplay returned
// CSS class names ("dead-field", "healthy") that were never keys in the colour
// map, so the FIELD column printed with no styling at all.
func TestFieldBadgesAreColourable(t *testing.T) {
	rows := map[string]score.Result{
		"healthy":  {Evidence: score.Evidence{FieldPopulate: fpv(1.0), BaselineFieldPopulate: 1.0}, PField: 1.0},
		"degraded": {Evidence: score.Evidence{FieldPopulate: fpv(0.5), BaselineFieldPopulate: 1.0}, PField: 0.5},
		"dead":     {Evidence: score.Evidence{FieldPopulate: fpv(0.0), BaselineFieldPopulate: 1.0}, PField: 0.0},
		"abstain":  {Evidence: score.Evidence{FieldPopulate: nil, BaselineFieldPopulate: 1.0}},
	}
	for name, r := range rows {
		_, badge := fieldDisplay(r)
		if got := colour("x", badge); got == "x" {
			t.Errorf("%s row: field badge %q is not in the colour map — column renders uncoloured", name, badge)
		}
	}
}

// TestDeadFieldVisuallyDistinctFromDegraded guards the other half: both used
// \033[33m, so the two verdicts were indistinguishable in a terminal.
func TestDeadFieldVisuallyDistinctFromDegraded(t *testing.T) {
	df := colour("x", verdictColor(score.VDeadField))
	dg := colour("x", verdictColor(score.VDegraded))
	if df == dg {
		t.Errorf("DEAD:FIELD and DEGRADED render identically (%q) — the distinction is invisible", stripANSI(df))
	}
}

// TestHeroDoesNotFabricateFieldPercent guards the "never guess when abstaining"
// principle: the hero printed "field 0%" for a null measurement.
func TestHeroDoesNotFabricateFieldPercent(t *testing.T) {
	results := score.ScoreAll([]score.Evidence{{
		Rule: "r.yml", State: "source-death", Liveness: "active",
		Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0,
	}})
	out := renderHTML("evidence.json", results)

	if strings.Contains(out, "field 0%") {
		t.Errorf("hero fabricated a percentage for an unmeasured field:\n%s", out)
	}
	if !strings.Contains(out, "field n/a") {
		t.Errorf("hero should report an unmeasured field as n/a:\n%s", out)
	}
}

// TestProbeErrorRendersNoMeasurement: a failed probe must not display the
// numbers it failed to collect, in either renderer.
func TestProbeErrorRendersNoMeasurement(t *testing.T) {
	results := score.ScoreAll([]score.Evidence{{
		Rule: "r.yml", State: "indexer-down", Liveness: "active",
		Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0,
		ProbeError: "connection refused",
	}})

	text := stripANSI(renderText("evidence.json", results))
	if strings.Contains(text, "64→0") {
		t.Errorf("text renderer showed a volume the probe never measured:\n%s", text)
	}
	if !strings.Contains(text, score.VProbeError) {
		t.Errorf("text renderer did not surface PROBE_ERROR:\n%s", text)
	}
	if !strings.Contains(text, "1 unknown") {
		t.Errorf("a failed probe should tally as unknown, not healthy or decayed:\n%s", text)
	}

	htmlOut := renderHTML("evidence.json", results)
	if strings.Contains(htmlOut, "64→0") {
		t.Errorf("html renderer showed a volume the probe never measured:\n%s", htmlOut)
	}
	if !strings.Contains(htmlOut, "probe-error") {
		t.Errorf("html renderer did not style PROBE_ERROR:\n%s", htmlOut)
	}
}

// TestTableRowsAlign: the borders reserved fewer columns than the cells used,
// so every row overflowed. Measure visible width rather than eyeballing it.
func TestTableRowsAlign(t *testing.T) {
	results := score.ScoreAll([]score.Evidence{
		{Rule: "ok.yml", State: "baseline", Liveness: "active", Volume: 64, BaselineVolume: 64, FieldPopulate: fpv(1.0), BaselineFieldPopulate: 1.0},
		{Rule: "gone.yml", State: "agent-gone", Liveness: "disconnected", Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0},
		{Rule: "drift.yml", State: "field-drift", Liveness: "active", Volume: 234, BaselineVolume: 64, FieldPopulate: fpv(0.0), BaselineFieldPopulate: 1.0},
		{Rule: "an_extremely_long_sigma_rule_name_that_overflows.yml", State: "drift", Liveness: "active", Volume: 10, BaselineVolume: 64, FieldPopulate: fpv(0.05), BaselineFieldPopulate: 1.0},
		{Rule: "probe.yml", State: "indexer-down", Liveness: "active", Volume: 0, BaselineVolume: 64, FieldPopulate: nil, BaselineFieldPopulate: 1.0, ProbeError: "connection refused"},
	})

	var widths []int
	var samples []string
	for _, line := range strings.Split(stripANSI(renderText("e.json", results)), "\n") {
		if !strings.HasPrefix(line, "│") && !strings.HasPrefix(line, "┌") &&
			!strings.HasPrefix(line, "├") && !strings.HasPrefix(line, "└") {
			continue
		}
		widths = append(widths, len([]rune(line)))
		samples = append(samples, line)
	}
	if len(widths) < 4 {
		t.Fatalf("expected a rendered table, found %d table lines", len(widths))
	}
	for i, w := range widths {
		if w != widths[0] {
			t.Errorf("table line %d is %d runes, header is %d:\n%s\n%s",
				i, w, widths[0], samples[0], samples[i])
		}
	}
}
