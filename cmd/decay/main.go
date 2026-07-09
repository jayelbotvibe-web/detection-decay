// decay — detection-decay scorer for purple-loop evidence
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

const version = "v0.1.1"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: decay [score] [flags]\n")
		os.Exit(2)
	}

	var evidencePath, format, outPath string

	// scoreCmd holds the flags for the 'score' subcommand
	scoreCmd := flag.NewFlagSet("score", flag.ExitOnError)
	scoreCmd.StringVar(&evidencePath, "evidence", "evidence.json", "path to evidence JSON file")
	scoreCmd.StringVar(&format, "format", "text", "output format: text, html")
	scoreCmd.StringVar(&outPath, "out", "", "output file path (for html format)")

	// Also support bare-flags form (no 'score' keyword)
	bareCmd := flag.NewFlagSet("decay", flag.ExitOnError)
	bareCmd.StringVar(&evidencePath, "evidence", "evidence.json", "path to evidence JSON file")
	bareCmd.StringVar(&format, "format", "text", "output format: text, html")
	bareCmd.StringVar(&outPath, "out", "", "output file path (for html format)")

	if os.Args[1] == "score" {
		scoreCmd.Parse(os.Args[2:])
	} else if strings.HasPrefix(os.Args[1], "-") {
		bareCmd.Parse(os.Args[1:])
	} else {
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "usage: decay [score] [flags]\n")
		os.Exit(2)
	}

	data, err := os.ReadFile(evidencePath)
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

	sort.Slice(results, func(i, j int) bool {
		return results[i].DecayScore > results[j].DecayScore
	})

	switch format {
	case "html":
		html := renderHTML(results, evidencePath)
		if outPath != "" {
			os.WriteFile(outPath, []byte(html), 0644)
			fmt.Printf("dashboard written to %s\n", outPath)
		} else {
			fmt.Print(html)
		}
	default:
		fmt.Print(renderText(results, evidencePath))
	}
}

func renderText(results []score.Result, evidencePath string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\033[1;36mdecay %s\033[0m — detection-decay scorer\n", version))
	sb.WriteString(fmt.Sprintf("evidence: %s\n\n", evidencePath))

	if len(results) == 0 {
		sb.WriteString("no evidence rows — nothing to score\n")
		return sb.String()
	}

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
		} else if float64(r.Volume) < 0.5*float64(r.BaselineVolume) {
			vol = colour(fmt.Sprintf("%-6d", r.Volume), "yellow")
		}

		field := ""
		if r.FieldPopulate == nil {
			field = colour("N/A    ", "gray")
		} else if *r.FieldPopulate < 0.5*r.BaselineFieldPopulate {
			field = colour(fmt.Sprintf("%.0f%%→%.0f%% ", r.BaselineFieldPopulate*100, *r.FieldPopulate*100), "red")
		} else {
			field = colour(fmt.Sprintf("%.0f%%     ", *r.FieldPopulate*100), "green")
		}

		decay := colour(fmt.Sprintf("%-5.2f", r.DecayScore), verdictColor(r.Verdict))
		verdict := colour(fmt.Sprintf("%-18s", r.Verdict), verdictColor(r.Verdict))

		sb.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │ %s │\n",
			namePad, live, vol, field, decay, verdict))
	}

	sb.WriteString("└──────────────────────────────────────┴──────┴────────┴───────┴───────┴────────────────────┘\n\n")

	sb.WriteString("\033[1mReason codes\033[0m\n")
	for _, r := range results {
		if r.Verdict == score.VHealthy {
			continue
		}
		vcol := verdictColor(r.Verdict)
		sb.WriteString(fmt.Sprintf("  %s\n", colour(r.Verdict, vcol)))
		sb.WriteString(fmt.Sprintf("  └ %s\n", r.Reason))
	}

	healthy := 0
	dead := 0
	worst := 0.0
	for _, r := range results {
		if r.Verdict == score.VHealthy {
			healthy++
		} else if r.Verdict == score.VDeadSource || r.Verdict == score.VDeadField {
			dead++
		}
		if r.DecayScore > worst {
			worst = r.DecayScore
		}
	}
	sb.WriteString(fmt.Sprintf("\n\033[1m%d evaluated · %d healthy · %d silently decayed · worst %.2f\033[0m\n",
		len(results), healthy, dead, worst))
	sb.WriteString("\033[90mA volume-only monitor catches source-death by luck — but MISSES field-drift entirely.\033[0m\n")

	return sb.String()
}

func renderHTML(results []score.Result, evidencePath string) string {
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
<div class="worst gray">no evidence rows — nothing to score</div>
</div></body></html>`, version, evidencePath))
		return sb.String()
	}

	worst := results[0]
	for _, r := range results {
		if r.DecayScore > worst.DecayScore {
			worst = r
		}
	}

	vcls := "healthy"
	if worst.Verdict == "DEAD:SOURCE" {
		vcls = "dead-source"
	} else if worst.Verdict == "DEAD:FIELD" {
		vcls = "dead-field"
	}
	sb.WriteString(fmt.Sprintf(`<div class="hero">
<h1>decay %s — detection-decay dashboard</h1>
<p>evidence: %s</p>
<div class="worst %s">%s</div>
<p>liveness %s · volume %d · field %.0f%% — %s</p>
</div>`, version, evidencePath, vcls, worst.Verdict, worst.Liveness, worst.Volume,
		func() float64 {
			if worst.FieldPopulate != nil {
				return *worst.FieldPopulate * 100
			}
			return 0
		}(),
		worst.Reason))

	sb.WriteString("<table><tr><th>RULE / STATE</th><th>LIVE</th><th>VOLUME</th><th>FIELD</th><th>DECAY</th><th>VERDICT</th></tr>")
	for _, r := range results {
		live := fmt.Sprintf(`<span class="healthy">%s</span>`, r.Liveness)
		if !strings.EqualFold(r.Liveness, "active") {
			live = fmt.Sprintf(`<span class="dead-source">%s</span>`, r.Liveness)
		}
		vol := fmt.Sprintf(`<span class="healthy">%d</span>`, r.Volume)
		if r.Volume == 0 {
			vol = fmt.Sprintf(`<span class="dead-source">%d→%d</span>`, r.BaselineVolume, r.Volume)
		}
		field := `<span class="gray">N/A</span>`
		if r.FieldPopulate != nil {
			if *r.FieldPopulate < 0.5 {
				field = fmt.Sprintf(`<span class="dead-field">%.0f%%→%.0f%%</span>`, r.BaselineFieldPopulate*100, *r.FieldPopulate*100)
			} else {
				field = fmt.Sprintf(`<span class="healthy">%.0f%%</span>`, *r.FieldPopulate*100)
			}
		}
		vcls := "healthy"
		if r.Verdict == "DEAD:SOURCE" {
			vcls = "dead-source"
		} else if r.Verdict == "DEAD:FIELD" {
			vcls = "dead-field"
		}
		verdict := fmt.Sprintf(`<span class="%s">%s</span>`, vcls, r.Verdict)

		sb.WriteString(fmt.Sprintf("<tr><td>%s / %s</td><td>%s</td><td>%s</td><td>%s</td><td>%.2f</td><td>%s</td></tr>",
			r.Rule, r.State, live, vol, field, r.DecayScore, verdict))
	}
	sb.WriteString("</table>")

	healthy := 0
	dead := 0
	for _, r := range results {
		if r.Verdict == "HEALTHY" {
			healthy++
		} else {
			dead++
		}
	}
	sb.WriteString(fmt.Sprintf(`<div class="footer">%d evaluated · %d healthy · %d silently decayed<br>A volume-only monitor catches source-death by luck — but MISSES field-drift entirely.</div>`,
		len(results), healthy, dead))

	sb.WriteString("</body></html>")
	return sb.String()
}

func padRight(s string, width int) string {
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
		return s[:width+len(s)-len(clean)]
	}
	return s + strings.Repeat(" ", width-len(clean))
}

func colour(s, c string) string {
	codes := map[string]string{
		"green":  "\033[32m",
		"red":    "\033[31m",
		"yellow": "\033[33m",
		"gray":   "\033[90m",
		"cyan":   "\033[36m",
		"amber":  "\033[33m",
	}
	if code, ok := codes[c]; ok {
		return code + s + "\033[0m"
	}
	return s
}

func verdictColor(v string) string {
	switch v {
	case "HEALTHY":
		return "green"
	case "DEAD:SOURCE":
		return "red"
	case "DEAD:FIELD":
		return "yellow"
	case "INSUFFICIENT_DATA":
		return "amber"
	default:
		return "gray"
	}
}
