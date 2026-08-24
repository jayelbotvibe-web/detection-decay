// decay — detection-decay scorer for purple-loop evidence
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jayelbotvibe-web/detection-decay/internal/calibrate"
	"github.com/jayelbotvibe-web/detection-decay/internal/history"
	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

const version = "v0.2.0"

func main() {
	scoreCmd := flag.NewFlagSet("score", flag.ExitOnError)
	evidencePath := scoreCmd.String("evidence", "evidence.json", "path to evidence JSON file")
	format := scoreCmd.String("format", "text", "output format: text, html, json")
	outPath := scoreCmd.String("out", "", "output file path (default stdout)")
	failOn := scoreCmd.String("fail-on", "none", "exit "+fmt.Sprint(exitDecay)+" when any row is at or worse than: none, degraded, dead, unknown")
	showVersion := scoreCmd.Bool("version", false, "print version and exit")
	historyDir := scoreCmd.String("history", "", "directory to persist runs and the trend index")
	baselinePath := scoreCmd.String("baselines", "", "baselines file from `decay calibrate`, used for rows carrying none")

	// Accept both `decay score [flags]` and `decay [flags]`.
	args := os.Args[1:]
	switch {
	case len(args) == 0:
		// defaults
	case args[0] == "calibrate":
		runCalibrate(args[1:])
		return
	case args[0] == "score":
		args = args[1:]
	case strings.HasPrefix(args[0], "-"):
		// bare-flags form
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", args[0], usage)
		os.Exit(exitUsage)
	}
	if err := scoreCmd.Parse(args); err != nil {
		os.Exit(exitUsage)
	}

	if *showVersion {
		fmt.Printf("decay %s\n", version)
		return
	}

	// Positional arguments used to be swallowed silently: `decay score foo.json`
	// scored evidence.json and exited 0, reporting on a file the user never named.
	if scoreCmd.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q — did you mean -evidence %s?\n%s",
			scoreCmd.Arg(0), scoreCmd.Arg(0), usage)
		os.Exit(exitUsage)
	}

	threshold, err := parseFailOn(*failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n%s", err, usage)
		os.Exit(exitUsage)
	}

	data, err := os.ReadFile(*evidencePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading evidence: %v\n", err)
		os.Exit(1)
	}
	// DisallowUnknownFields turns a mistyped key into a parse error instead of a
	// silent default. A typo'd "volume" used to decode as 0 and report a total
	// source outage that never happened.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var evs []score.Evidence
	if err := dec.Decode(&evs); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing evidence: %v\n", err)
		os.Exit(1)
	}

	if *baselinePath != "" {
		evs = applyBaselines(*baselinePath, evs)
	}

	if errs := score.Validate(evs); len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "error: %s has %d invalid row(s):\n", *evidencePath, len(errs))
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %v\n", e)
		}
		os.Exit(1)
	}

	results := score.ScoreAll(evs)

	sortResults(results)

	// History is written before rendering so the run artifact and the terminal
	// output describe the same thing, including what moved since last time.
	var ch *changes
	if *historyDir != "" {
		ch = recordRun(*historyDir, *evidencePath, results)
	}

	var out string
	switch *format {
	case "html":
		out = renderHTML(*evidencePath, results)
	case "json":
		out = renderJSON(*evidencePath, results, ch)
	case "text":
		out = renderText(*evidencePath, results) + renderChanges(ch)
	default:
		// An unrecognised format used to fall through to text and exit 0, so
		// `--format json` silently produced a terminal table.
		fmt.Fprintf(os.Stderr, "unknown format %q — expected text, html or json\n", *format)
		os.Exit(exitUsage)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(out), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outPath, err)
			os.Exit(exitIO)
		}
		if *format == "html" {
			fmt.Printf("dashboard written to %s\n", *outPath)
		}
	} else {
		fmt.Print(out)
	}

	// Exit non-zero so the tool can gate a cron job or a CI step. Without this
	// it always exited 0 and nothing could act on its findings.
	if worst := worstRank(results); worst >= threshold {
		fmt.Fprintf(os.Stderr, "decay detected: %s (--fail-on %s)\n", rankName(worst), *failOn)
		os.Exit(exitDecay)
	}
}

// Exit codes. These are the tool's contract with a scheduler.
const (
	exitIO    = 1 // I/O or parse failure
	exitUsage = 2 // bad invocation
	exitDecay = 3 // scored successfully, and found decay at or above --fail-on
)

const usage = `usage: decay [score] [-evidence file] [-format text|html|json] [-out file]
             [-fail-on none|degraded|dead|unknown] [-history dir]
             [-baselines file] [-version]
       decay calibrate -history dir [-out file] [-window N] [-min-samples N]
`

// Verdict severity ranks, used only by --fail-on.
const (
	rankHealthy = iota
	rankUnknown // measured nothing: INSUFFICIENT_DATA, PROBE_ERROR
	rankDegraded
	rankDead
	rankNever = 99 // --fail-on none
)

func rankName(r int) string {
	switch r {
	case rankDead:
		return "dead"
	case rankDegraded:
		return "degraded"
	case rankUnknown:
		return "unknown"
	default:
		return "healthy"
	}
}

// parseFailOn maps the flag to the lowest rank that should fail the run.
func parseFailOn(v string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none":
		return rankNever, nil
	case "unknown":
		return rankUnknown, nil
	case "degraded":
		return rankDegraded, nil
	case "dead":
		return rankDead, nil
	default:
		return 0, fmt.Errorf("unknown -fail-on %q — expected none, degraded, dead or unknown", v)
	}
}

func verdictRank(v string) int {
	switch v {
	case score.VDeadSource, score.VDeadField:
		return rankDead
	case score.VDegraded:
		return rankDegraded
	case score.VInsufficientData, score.VProbeError:
		return rankUnknown
	default:
		return rankHealthy
	}
}

func worstRank(results []score.Result) int {
	worst := rankHealthy
	for _, r := range results {
		if k := verdictRank(r.Verdict); k > worst {
			worst = k
		}
	}
	return worst
}

// ---------- shared helpers ----------

// sortResults orders rows worst-decay-first, with a rule-name tiebreak so the
// output is diffable across runs.
func sortResults(results []score.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].DecayScore != results[j].DecayScore {
			return results[i].DecayScore > results[j].DecayScore
		}
		return results[i].Rule < results[j].Rule
	})
}

// summary holds computed tallies, shared by both renderers.
type summary struct {
	evaluated int
	healthy   int
	dead      int
	degraded  int
	silent    int // dead + degraded
	unknown   int // insufficient data or failed probe — measured nothing
	worst     float64
}

func tally(results []score.Result) summary {
	s := summary{evaluated: len(results)}
	for _, r := range results {
		switch r.Verdict {
		case score.VHealthy:
			s.healthy++
		case score.VDeadSource, score.VDeadField:
			s.dead++
		case score.VDegraded:
			s.degraded++
		case score.VInsufficientData, score.VProbeError:
			s.unknown++
		}
		if r.DecayScore > s.worst {
			s.worst = r.DecayScore
		}
	}
	s.silent = s.dead + s.degraded
	return s
}

// fieldDisplay returns the styled field-column cell for a result.
// Both renderers use the same banding via PField.
func fieldDisplay(r score.Result) (text string, badge string) {
	// A failed probe measured nothing; it must not render as a measurement.
	if r.ProbeError != "" {
		return "n/a", "gray"
	}
	if r.FieldPopulate == nil {
		return "N/A", "gray"
	}
	cur := *r.FieldPopulate * 100
	bl := r.BaselineFieldPopulate * 100
	switch {
	case r.PField < score.DeadThreshold:
		return fmt.Sprintf("%.0f%%→%.0f%%", bl, cur), "dead-field"
	case r.PField < score.HealthyThreshold:
		return fmt.Sprintf("%.0f%%→%.0f%%", bl, cur), "degraded"
	default:
		return fmt.Sprintf("%.0f%%", cur), "healthy"
	}
}

// verdictCSS returns the CSS class for a verdict.
func verdictCSS(v string) string {
	switch v {
	case score.VHealthy:
		return "healthy"
	case score.VDegraded:
		return "degraded"
	case score.VDeadSource:
		return "dead-source"
	case score.VDeadField:
		return "dead-field"
	case score.VInsufficientData:
		return "gray"
	case score.VProbeError:
		return "probe-error"
	default:
		return "gray"
	}
}

// ---------- text renderer ----------

func renderText(evidencePath string, results []score.Result) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("\033[1;36mdecay %s\033[0m — detection-decay scorer\n", version))
	sb.WriteString(fmt.Sprintf("evidence: %s\n\n", evidencePath))

	if len(results) == 0 {
		sb.WriteString("no evidence rows — nothing to score\n")
		return sb.String()
	}

	// Table
	sb.WriteString("┌──────────────────────────────────────┬────────┬────────┬───────────┬───────┬────────────────────┐\n")
	sb.WriteString("│ RULE / STATE                         │ LIVE   │ VOLUME │ FIELD     │ DECAY │ VERDICT            │\n")
	sb.WriteString("├──────────────────────────────────────┼────────┼────────┼───────────┼───────┼────────────────────┤\n")

	for _, r := range results {
		name := fmt.Sprintf("%s / %s", r.Rule, r.State)
		namePad := padRight(name, 36)

		live := padRight(colour("active", "green"), 6)
		if !strings.EqualFold(r.Liveness, "active") {
			live = padRight(colour(padRight(r.Liveness, 6), "red"), 6)
		}

		var vol string
		switch {
		case r.ProbeError != "":
			vol = colour(fmt.Sprintf("%-6s", "n/a"), "gray")
		case r.Volume == 0:
			vol = colour(fmt.Sprintf("%-6s", fmt.Sprintf("%d→%d", r.BaselineVolume, r.Volume)), "red")
		case r.PSource < score.HealthyThreshold:
			vol = colour(fmt.Sprintf("%-6d", r.Volume), "yellow")
		default:
			vol = colour(fmt.Sprintf("%-6d", r.Volume), "green")
		}

		fieldStr, fbadge := fieldDisplay(r)
		fieldCell := colour(fmt.Sprintf("%-9s", fieldStr), fbadge)

		decay := colour(fmt.Sprintf("%-5.2f", r.DecayScore), verdictColor(r.Verdict))
		verdict := colour(fmt.Sprintf("%-18s", r.Verdict), verdictColor(r.Verdict))

		sb.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │ %s │\n",
			namePad, live, vol, fieldCell, decay, verdict))
	}

	sb.WriteString("└──────────────────────────────────────┴────────┴────────┴───────────┴───────┴────────────────────┘\n\n")

	// Reason codes
	sb.WriteString("\033[1mReason codes\033[0m\n")
	for _, r := range results {
		if r.Verdict == score.VHealthy {
			continue
		}
		vcol := verdictColor(r.Verdict)
		sb.WriteString(fmt.Sprintf("  %s\n", colour(r.Verdict, vcol)))
		sb.WriteString(fmt.Sprintf("  └ %s\n", r.Reason))
	}

	// Summary
	s := tally(results)
	sb.WriteString(fmt.Sprintf("\n\033[1m%d evaluated · %d healthy · %d silently decayed · %d unknown · worst %.2f\033[0m\n",
		s.evaluated, s.healthy, s.silent, s.unknown, s.worst))
	sb.WriteString("\033[90mA volume-only monitor catches source-death by luck — but MISSES field-drift entirely.\033[0m\n")

	return sb.String()
}

// ---------- HTML renderer ----------

func renderHTML(evidencePath string, results []score.Result) string {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>decay dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:2rem}
.hero{border:1px solid #30363d;border-radius:6px;padding:1.5rem;margin-bottom:2rem}
.hero h1{color:#58a6ff;font-size:1.2rem;margin-bottom:0.5rem}
.hero .worst{font-size:2rem;font-weight:bold}
.dead-source{color:#f85149}
.dead-field{color:#f0883e}
.degraded{color:#d2991d}
.healthy{color:#3fb950}
.gray{color:#8b949e}
.probe-error{color:#a371f7}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th,td{padding:0.5rem 0.75rem;text-align:left;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:normal;font-size:0.85rem}
.footer{margin-top:2rem;color:#8b949e;font-size:0.85rem}
</style></head><body>`)

	if len(results) == 0 {
		sb.WriteString(fmt.Sprintf(`<div class="hero">
<h1>decay %s — detection-decay dashboard</h1>
<p>evidence: %s</p>
<p class="gray">no evidence rows — nothing to score</p>
</div></body></html>`, version, html.EscapeString(evidencePath)))
		return sb.String()
	}

	// Worst is results[0] (sorted by decay desc).
	worst := results[0]

	// Hero
	hcls := verdictCSS(worst.Verdict)
	// Never print a number for an unmeasured field. Rendering 0% for a null
	// measurement is exactly the guess the scorer abstains from making.
	fieldPct, volPct := "n/a", fmt.Sprintf("%d", worst.Volume)
	if worst.FieldPopulate != nil && worst.ProbeError == "" {
		fieldPct = fmt.Sprintf("%.0f%%", *worst.FieldPopulate*100)
	}
	if worst.ProbeError != "" {
		volPct = "n/a"
	}
	sb.WriteString(fmt.Sprintf(`<div class="hero">
<h1>decay %s — detection-decay dashboard</h1>
<p>evidence: %s</p>
<div class="worst %s">%s</div>
<p>liveness %s · volume %s · field %s — %s</p>
</div>`,
		version,
		html.EscapeString(evidencePath),
		html.EscapeString(hcls),
		html.EscapeString(worst.Verdict),
		html.EscapeString(worst.Liveness),
		volPct,
		fieldPct,
		html.EscapeString(worst.Reason),
	))

	// Table
	sb.WriteString("<table><tr><th>RULE / STATE</th><th>LIVE</th><th>VOLUME</th><th>FIELD</th><th>DECAY</th><th>VERDICT</th></tr>")
	for _, r := range results {
		live := fmt.Sprintf(`<span class="healthy">%s</span>`, html.EscapeString(r.Liveness))
		if !strings.EqualFold(r.Liveness, "active") {
			live = fmt.Sprintf(`<span class="dead-source">%s</span>`, html.EscapeString(r.Liveness))
		}

		var vol string
		switch {
		case r.ProbeError != "":
			vol = `<span class="gray">n/a</span>`
		case r.Volume == 0:
			vol = fmt.Sprintf(`<span class="dead-source">%d→%d</span>`, r.BaselineVolume, r.Volume)
		case r.PSource < score.HealthyThreshold:
			vol = fmt.Sprintf(`<span class="degraded">%d</span>`, r.Volume)
		default:
			vol = fmt.Sprintf(`<span class="healthy">%d</span>`, r.Volume)
		}

		fieldStr, fbadge := fieldDisplay(r)
		fieldCell := fmt.Sprintf(`<span class="gray">%s</span>`, html.EscapeString(fieldStr))
		if fbadge != "gray" {
			fieldCell = fmt.Sprintf(`<span class="%s">%s</span>`, fbadge, html.EscapeString(fieldStr))
		}

		vcls := verdictCSS(r.Verdict)

		sb.WriteString(fmt.Sprintf("<tr><td>%s / %s</td><td>%s</td><td>%s</td><td>%s</td><td>%.2f</td><td><span class=\"%s\">%s</span></td></tr>",
			html.EscapeString(r.Rule), html.EscapeString(r.State),
			live, vol, fieldCell, r.DecayScore,
			html.EscapeString(vcls), html.EscapeString(r.Verdict),
		))
	}
	sb.WriteString("</table>")

	s := tally(results)
	sb.WriteString(fmt.Sprintf(`<div class="footer">%d evaluated · %d healthy · %d silently decayed · %d unknown<br>A volume-only monitor catches source-death by luck — but MISSES field-drift entirely.</div>`,
		s.evaluated, s.healthy, s.silent, s.unknown))

	sb.WriteString("</body></html>")
	return sb.String()
}

// ---------- display helpers ----------

func padRight(s string, width int) string {
	// Strip ANSI codes before measuring
	clean := s
	for {
		start := strings.Index(clean, "\033[")
		if start < 0 {
			break
		}
		end := strings.Index(clean[start:], "m")
		if end < 0 {
			break
		}
		clean = clean[:start] + clean[start+end+1:]
	}
	n := utf8.RuneCountInString(clean)
	if n == width {
		return s
	}
	if n > width {
		if clean != s || width < 1 {
			return s // coloured: truncating would cut the reset sequence
		}
		return string([]rune(s)[:width-1]) + "…"
	}
	return s + strings.Repeat(" ", width-n)
}

func colour(s, c string) string {
	// Keys cover both the semantic names verdictColor returns and the CSS class
	// names fieldDisplay/verdictCSS return, so a badge that styles the dashboard
	// also colours the terminal. Unmapped keys rendered as plain text, which is
	// why the FIELD column used to print uncoloured.
	//
	// amber is a distinct 256-colour orange, not another \033[33m — DEAD:FIELD and
	// DEGRADED were previously indistinguishable in the terminal.
	codes := map[string]string{
		"green":       "\033[32m",
		"red":         "\033[31m",
		"yellow":      "\033[33m",
		"gray":        "\033[90m",
		"cyan":        "\033[36m",
		"amber":       "\033[38;5;208m",
		"magenta":     "\033[35m",
		"healthy":     "\033[32m",
		"degraded":    "\033[33m",
		"dead-source": "\033[31m",
		"dead-field":  "\033[38;5;208m",
		"probe-error": "\033[35m",
	}
	if code, ok := codes[c]; ok {
		return code + s + "\033[0m"
	}
	return s
}

func verdictColor(v string) string {
	switch v {
	case score.VHealthy:
		return "green"
	case score.VDegraded:
		return "yellow"
	case score.VDeadSource:
		return "red"
	case score.VDeadField:
		return "amber"
	case score.VInsufficientData:
		return "gray"
	case score.VProbeError:
		return "magenta"
	default:
		return "gray"
	}
}

// ---------- json renderer ----------

// jsonSummary is persisted as numbers, deliberately. Nothing downstream should
// ever have to recover a figure by re-parsing the prose that describes it.
type jsonSummary struct {
	Evaluated    int     `json:"evaluated"`
	Healthy      int     `json:"healthy"`
	Degraded     int     `json:"degraded"`
	Dead         int     `json:"dead"`
	Silent       int     `json:"silent"`
	Unknown      int     `json:"unknown"`
	WorstDecay   float64 `json:"worst_decay"`
	WorstVerdict string  `json:"worst_verdict"`
}

type jsonReport struct {
	Version  string         `json:"version"`
	Evidence string         `json:"evidence"`
	Summary  jsonSummary    `json:"summary"`
	Changes  *changes       `json:"changes,omitempty"`
	Results  []score.Result `json:"results"`
}

// changes is what moved since the previous indexed run. Reading a full table
// every hour is how a monitor gets ignored; what an operator needs is the diff.
type changes struct {
	PreviousRun string   `json:"previous_run"`
	New         []string `json:"new"`     // rule/state not seen in the previous run
	Changed     []string `json:"changed"` // same rule/state, different finding
	Removed     []string `json:"removed"` // rule/state absent from this run
	Unchanged   int      `json:"unchanged"`
}

// worstVerdict returns the most severe verdict present, by rank rather than by
// decay score — PROBE_ERROR carries no decay but must not be reported as the
// mildest row in the set.
func worstVerdict(results []score.Result) string {
	worst, name := rankHealthy, score.VHealthy
	for _, r := range results {
		if k := verdictRank(r.Verdict); k > worst {
			worst, name = k, r.Verdict
		}
	}
	if len(results) == 0 {
		return ""
	}
	return name
}

func buildReport(evidencePath string, results []score.Result, ch *changes) jsonReport {
	s := tally(results)
	if results == nil {
		results = []score.Result{}
	}
	return jsonReport{
		Changes:  ch,
		Version:  version,
		Evidence: evidencePath,
		Summary: jsonSummary{
			Evaluated:    s.evaluated,
			Healthy:      s.healthy,
			Degraded:     s.degraded,
			Dead:         s.dead,
			Silent:       s.silent,
			Unknown:      s.unknown,
			WorstDecay:   s.worst,
			WorstVerdict: worstVerdict(results),
		},
		Results: results,
	}
}

func renderJSON(evidencePath string, results []score.Result, ch *changes) string {
	b, err := json.MarshalIndent(buildReport(evidencePath, results, ch), "", "  ")
	if err != nil {
		// Unreachable for these types, but never emit malformed JSON silently.
		fmt.Fprintf(os.Stderr, "error encoding report: %v\n", err)
		os.Exit(exitIO)
	}
	return string(b) + "\n"
}

// ---------- run history ----------

// findingKey identifies the entity being monitored. A rule/state pair persists
// across runs; the finding attached to it is what moves.
func findingKey(r score.Result) string {
	return fmt.Sprintf("%s / %s", r.Rule, r.State)
}

// measured reports whether a run produced at least one usable measurement.
// A run where every row failed to probe carries no information about detection
// health, and indexing it would put a fake "0.00 worst decay" point on the
// trend line — exactly the false reassurance this tool exists to prevent.
func measured(results []score.Result) bool {
	for _, r := range results {
		if verdictRank(r.Verdict) != rankUnknown {
			return true
		}
	}
	return false
}

// diffAgainst compares this run with the previous one.
//
// Fingerprints carry the verdict and the banded decay score, so "did this
// finding move" is a hash comparison rather than a field-by-field diff. But the
// comparison is keyed on the rule/state *entity*, not the fingerprint alone:
// keying on the hash reports a verdict transition as an unrelated arrival and
// departure, which reads as two incidents instead of one.
func diffAgainst(results []score.Result, prevResults []score.Result, prevID string) *changes {
	prev := make(map[string]score.Result, len(prevResults))
	for _, r := range prevResults {
		prev[findingKey(r)] = r
	}

	ch := &changes{PreviousRun: prevID, New: []string{}, Changed: []string{}, Removed: []string{}}
	seen := make(map[string]bool, len(results))

	for _, r := range results {
		key := findingKey(r)
		seen[key] = true
		was, existed := prev[key]
		switch {
		case !existed:
			ch.New = append(ch.New, fmt.Sprintf("%s — %s", key, r.Verdict))
		case was.Fingerprint != r.Fingerprint:
			ch.Changed = append(ch.Changed, fmt.Sprintf("%s — %s → %s (decay %.2f → %.2f)",
				key, was.Verdict, r.Verdict, was.DecayScore, r.DecayScore))
		default:
			ch.Unchanged++
		}
	}

	for key, r := range prev {
		if !seen[key] {
			ch.Removed = append(ch.Removed, fmt.Sprintf("%s — was %s", key, r.Verdict))
		}
	}
	// Map iteration is unordered; sort so the output is diffable across runs.
	sort.Strings(ch.Removed)
	return ch
}

// recordRun persists the run and returns what changed since the last one.
//
// History failures are reported but never fatal: losing a trend point is not a
// reason to discard a scoring run the operator asked for.
func recordRun(dir, evidencePath string, results []score.Result) *changes {
	store := &history.Store{Dir: dir}

	var ch *changes
	if prev, err := store.Latest(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else if prev != nil {
		if data, err := store.LoadRun(prev.ID); err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot read previous run %s: %v\n", prev.ID, err)
		} else {
			var prevRep jsonReport
			if err := json.Unmarshal(data, &prevRep); err != nil {
				fmt.Fprintf(os.Stderr, "warning: previous run %s is unreadable: %v\n", prev.ID, err)
			} else {
				ch = diffAgainst(results, prevRep.Results, prev.ID)
			}
		}
	}

	report, err := json.MarshalIndent(buildReport(evidencePath, results, ch), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot encode run: %v\n", err)
		return ch
	}

	id := store.NewID(time.Now())
	if _, err := store.Save(id, append(report, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot save run: %v\n", err)
		return ch
	}

	// The artifact is kept either way; only the index is gated. A run you
	// cannot trust is exactly the one you want to inspect afterwards.
	if !measured(results) {
		fmt.Fprintf(os.Stderr, "warning: run %s measured nothing — saved but not indexed\n", id)
		return ch
	}

	s := tally(results)
	if err := store.Append(history.Entry{
		ID:           id,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Evidence:     evidencePath,
		Evaluated:    s.evaluated,
		Healthy:      s.healthy,
		Silent:       s.silent,
		Unknown:      s.unknown,
		WorstDecay:   s.worst,
		WorstVerdict: worstVerdict(results),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot index run: %v\n", err)
	}
	return ch
}

// renderChanges appends the run-over-run diff to the text output. Reading a
// full table every hour is how a monitor gets ignored; the diff is the point.
func renderChanges(ch *changes) string {
	if ch == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n\033[1mChanges since %s\033[0m\n", ch.PreviousRun))
	if len(ch.New) == 0 && len(ch.Changed) == 0 && len(ch.Removed) == 0 {
		sb.WriteString(colour("  nothing changed\n", "gray"))
	}
	for _, l := range ch.Changed {
		sb.WriteString(colour(fmt.Sprintf("  ~ %s\n", l), "yellow"))
	}
	for _, l := range ch.New {
		sb.WriteString(colour(fmt.Sprintf("  + %s\n", l), "red"))
	}
	for _, l := range ch.Removed {
		sb.WriteString(colour(fmt.Sprintf("  - %s\n", l), "gray"))
	}
	sb.WriteString(colour(fmt.Sprintf("  %d unchanged\n", ch.Unchanged), "gray"))
	return sb.String()
}

// ---------- calibration ----------

// applyBaselines fills in baselines for rows that carry none. A missing or
// unreadable baselines file is fatal: the operator asked for derived baselines,
// and silently scoring without them would produce a table of INSUFFICIENT_DATA
// that looks like a telemetry problem rather than a missing file.
func applyBaselines(path string, evs []score.Evidence) []score.Evidence {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading baselines: %v\n", err)
		os.Exit(exitIO)
	}
	var f calibrate.File
	if err := json.Unmarshal(data, &f); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing baselines: %v\n", err)
		os.Exit(exitIO)
	}
	out, warnings := calibrate.Apply(evs, f, time.Now())
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	return out
}

func runCalibrate(args []string) {
	fs := flag.NewFlagSet("calibrate", flag.ExitOnError)
	historyDir := fs.String("history", "", "run history directory (required)")
	outPath := fs.String("out", "baselines.json", "output path, or - for stdout")
	window := fs.Int("window", 30, "consider at most this many recent runs")
	minSamples := fs.Int("min-samples", 3, "healthy observations required before a baseline is published")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitUsage)
	}
	if *historyDir == "" {
		fmt.Fprintf(os.Stderr, "calibrate: -history is required\n%s", usage)
		os.Exit(exitUsage)
	}
	if *minSamples < 1 {
		fmt.Fprintf(os.Stderr, "calibrate: -min-samples must be at least 1\n")
		os.Exit(exitUsage)
	}

	store := &history.Store{Dir: *historyDir}
	entries, err := store.Entries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading history: %v\n", err)
		os.Exit(exitIO)
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "error: no runs in %s — score with -history first\n", *historyDir)
		os.Exit(exitIO)
	}

	runs := make([][]byte, 0, len(entries))
	for _, e := range entries {
		data, err := store.LoadRun(e.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping run %s: %v\n", e.ID, err)
			continue
		}
		runs = append(runs, data)
	}

	f, warnings := calibrate.Derive(runs, *window, *minSamples, time.Now())
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding baselines: %v\n", err)
		os.Exit(exitIO)
	}
	out = append(out, '\n')

	if *outPath == "-" {
		os.Stdout.Write(out)
	} else if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outPath, err)
		os.Exit(exitIO)
	} else {
		fmt.Fprintf(os.Stderr, "derived %d baseline(s) from %d run(s) → %s\n",
			len(f.Baselines), len(runs), *outPath)
	}

	// No baselines is not a crash, but it is not success either: scoring against
	// this file would report INSUFFICIENT_DATA for everything.
	if len(f.Baselines) == 0 {
		os.Exit(exitIO)
	}
}
