// decay — detection-decay scorer for purple-loop evidence
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

const version = "v0.1.1"

func main() {
	scoreCmd := flag.NewFlagSet("score", flag.ExitOnError)
	evidencePath := scoreCmd.String("evidence", "evidence.json", "path to evidence JSON file")
	format := scoreCmd.String("format", "text", "output format: text, html")
	outPath := scoreCmd.String("out", "", "output file path (for html format)")

	// Accept both `decay score [flags]` and `decay [flags]`.
	args := os.Args[1:]
	switch {
	case len(args) == 0:
		// defaults
	case args[0] == "score":
		args = args[1:]
	case strings.HasPrefix(args[0], "-"):
		// bare-flags form
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: decay [score] [-evidence file] [-format text|html] [-out file]\n", args[0])
		os.Exit(2)
	}
	if err := scoreCmd.Parse(args); err != nil {
		os.Exit(2)
	}

	data, err := os.ReadFile(*evidencePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading evidence: %v\n", err)
		os.Exit(1)
	}
	var evs []score.Evidence
	if err := json.Unmarshal(data, &evs); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing evidence: %v\n", err)
		os.Exit(1)
	}

	results := score.ScoreAll(evs)

	// Sort: worst decay first, tiebreak on rule name for stable output.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].DecayScore != results[j].DecayScore {
			return results[i].DecayScore > results[j].DecayScore
		}
		return results[i].Rule < results[j].Rule
	})

	switch *format {
	case "html":
		htmlOut := renderHTML(*evidencePath, results)
		if *outPath != "" {
			if err := os.WriteFile(*outPath, []byte(htmlOut), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outPath, err)
				os.Exit(1)
			}
			fmt.Printf("dashboard written to %s\n", *outPath)
		} else {
			fmt.Print(htmlOut)
		}
	default:
		fmt.Print(renderText(*evidencePath, results))
	}
}

// ---------- shared helpers ----------

// summary holds computed tallies, shared by both renderers.
type summary struct {
	evaluated int
	healthy   int
	dead      int
	degraded  int
	silent    int // dead + degraded
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
	default:
		return "gray"
	}
}

// heroClass returns the CSS class for the hero worst-verdict display.
func heroClass(v string) string {
	switch v {
	case score.VDeadSource:
		return "dead-source"
	case score.VDeadField:
		return "dead-field"
	case score.VDegraded:
		return "degraded"
	case score.VInsufficientData:
		return "gray"
	default:
		return "healthy"
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
	sb.WriteString("┌──────────────────────────────────────┬──────┬────────┬───────┬───────┬────────────────────┐\n")
	sb.WriteString("│ RULE / STATE                         │ LIVE │ VOLUME │ FIELD │ DECAY │ VERDICT            │\n")
	sb.WriteString("├──────────────────────────────────────┼──────┼────────┼───────┼───────┼────────────────────┤\n")

	for _, r := range results {
		name := fmt.Sprintf("%s / %s", r.Rule, r.State)
		namePad := padRight(name, 36)

		live := colour("active", "green")
		if !strings.EqualFold(r.Liveness, "active") {
			live = colour(r.Liveness, "red")
		}

		vol := colour(fmt.Sprintf("%-6d", r.Volume), "green")
		if r.Volume == 0 {
			vol = colour(fmt.Sprintf("%-6s", fmt.Sprintf("%d→%d", r.BaselineVolume, r.Volume)), "red")
		} else if r.PSource < score.HealthyThreshold {
			vol = colour(fmt.Sprintf("%-6d", r.Volume), "yellow")
		}

		fieldStr, fbadge := fieldDisplay(r)
		fieldCell := colour(fmt.Sprintf("%-7s", fieldStr), fbadge)
		if fbadge == "gray" {
			fieldCell = colour(fmt.Sprintf("%-7s", fieldStr), "gray")
		}

		decay := colour(fmt.Sprintf("%-5.2f", r.DecayScore), verdictColor(r.Verdict))
		verdict := colour(fmt.Sprintf("%-18s", r.Verdict), verdictColor(r.Verdict))

		sb.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │ %s │\n",
			namePad, live, vol, fieldCell, decay, verdict))
	}

	sb.WriteString("└──────────────────────────────────────┴──────┴────────┴───────┴───────┴────────────────────┘\n\n")

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
	sb.WriteString(fmt.Sprintf("\n\033[1m%d evaluated · %d healthy · %d silently decayed · worst %.2f\033[0m\n",
		s.evaluated, s.healthy, s.silent, s.worst))
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
	hcls := heroClass(worst.Verdict)
	fieldPct := 0.0
	if worst.FieldPopulate != nil {
		fieldPct = *worst.FieldPopulate * 100
	}
	sb.WriteString(fmt.Sprintf(`<div class="hero">
<h1>decay %s — detection-decay dashboard</h1>
<p>evidence: %s</p>
<div class="worst %s">%s</div>
<p>liveness %s · volume %d · field %.0f%% — %s</p>
</div>`,
		version,
		html.EscapeString(evidencePath),
		html.EscapeString(hcls),
		html.EscapeString(worst.Verdict),
		html.EscapeString(worst.Liveness),
		worst.Volume,
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

		vol := fmt.Sprintf(`<span class="healthy">%d</span>`, r.Volume)
		if r.Volume == 0 {
			vol = fmt.Sprintf(`<span class="dead-source">%d→%d</span>`, r.BaselineVolume, r.Volume)
		} else if r.PSource < score.HealthyThreshold {
			vol = fmt.Sprintf(`<span class="degraded">%d</span>`, r.Volume)
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
	sb.WriteString(fmt.Sprintf(`<div class="footer">%d evaluated · %d healthy · %d silently decayed<br>A volume-only monitor catches source-death by luck — but MISSES field-drift entirely.</div>`,
		s.evaluated, s.healthy, s.silent))

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
	if len(clean) >= width {
		return s[:width+len(s)-len(clean)] // approximate
	}
	return s + strings.Repeat(" ", width-len(clean))
}

func colour(s, c string) string {
	codes := map[string]string{
		"green":    "\033[32m",
		"red":      "\033[31m",
		"yellow":   "\033[33m",
		"gray":     "\033[90m",
		"cyan":     "\033[36m",
		"amber":    "\033[33m",
		"degraded": "\033[33m",
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
	default:
		return "gray"
	}
}
