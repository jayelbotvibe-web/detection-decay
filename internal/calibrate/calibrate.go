// Package calibrate derives healthy baselines from recorded run history.
//
// Baselines were hand-written once and never revisited, which makes every
// seasonal trough look like decay: a rule that fires 3000 times on a Tuesday
// afternoon and 400 times at 3am Sunday reports DEGRADED every weekend against
// a fixed number.
//
// The load-bearing rule here is that only observations that were themselves
// healthy contribute. A rolling baseline computed from every observation
// ratchets downward — a source that dies and stays dead drags its own baseline
// to zero, and within a few runs a total outage reads as perfectly healthy.
// That is the standard way rolling baselines fail, and it fails silently, which
// is the one failure mode this tool exists to prevent.
package calibrate

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jayelbotvibe-web/detection-decay/internal/score"
)

// Baseline is a derived healthy baseline for one rule/state.
type Baseline struct {
	Volume        int     `json:"volume"`
	FieldPopulate float64 `json:"field_populate"`
	Samples       int     `json:"samples"`
	ObservedAt    string  `json:"observed_at"`
}

// File is the on-disk baselines document.
type File struct {
	GeneratedAt string              `json:"generated_at"`
	Window      int                 `json:"window"`
	MinSamples  int                 `json:"min_samples"`
	Baselines   map[string]Baseline `json:"baselines"`
}

// runDoc is the slice of a run artifact calibration needs. Declared here rather
// than shared with the command so storage stays decoupled from the report shape.
type runDoc struct {
	Results []score.Result `json:"results"`
}

// Key identifies the entity a baseline belongs to.
func Key(rule, state string) string { return rule + "|" + state }

// observation is one healthy measurement of one entity.
type observation struct {
	volume   int
	populate float64
	hasField bool
	at       string
}

// median of a sorted-in-place copy. Median rather than mean: a single outlier
// run must not move the baseline, and outliers are exactly what a decaying
// pipeline produces.
func medianInt(v []int) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int(nil), v...)
	sort.Ints(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

func medianFloat(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// Derive computes baselines from run artifacts, newest last.
//
// window bounds how many recent runs are considered; minSamples is how many
// healthy observations an entity needs before its baseline is trusted. Entities
// with fewer are omitted entirely rather than published with a thin baseline —
// a baseline derived from one observation is just that observation.
func Derive(runs [][]byte, window, minSamples int, now time.Time) (File, []string) {
	var warnings []string

	if window > 0 && len(runs) > window {
		runs = runs[len(runs)-window:]
	}

	obs := map[string][]observation{}
	for i, raw := range runs {
		var doc runDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			warnings = append(warnings, fmt.Sprintf("run %d is unreadable and was skipped: %v", i, err))
			continue
		}
		for _, r := range doc.Results {
			// The ratchet guard. Anything short of HEALTHY is either decay or an
			// unmeasured gate, and neither describes what normal looks like.
			if r.Verdict != score.VHealthy {
				continue
			}
			o := observation{volume: r.Volume}
			if r.FieldPopulate != nil {
				o.populate, o.hasField = *r.FieldPopulate, true
			}
			obs[Key(r.Rule, r.State)] = append(obs[Key(r.Rule, r.State)], o)
		}
	}

	out := File{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Window:      window,
		MinSamples:  minSamples,
		Baselines:   map[string]Baseline{},
	}

	thin := 0
	for key, list := range obs {
		if len(list) < minSamples {
			thin++
			continue
		}
		vols := make([]int, 0, len(list))
		pops := make([]float64, 0, len(list))
		for _, o := range list {
			vols = append(vols, o.volume)
			if o.hasField {
				pops = append(pops, o.populate)
			}
		}
		b := Baseline{
			Volume:     medianInt(vols),
			Samples:    len(list),
			ObservedAt: out.GeneratedAt,
		}
		if len(pops) > 0 {
			b.FieldPopulate = medianFloat(pops)
		}
		out.Baselines[key] = b
	}

	if thin > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d rule/state pair(s) had fewer than %d healthy observations and were omitted — "+
				"a baseline derived from one observation is just that observation", thin, minSamples))
	}
	if len(out.Baselines) == 0 {
		warnings = append(warnings, "no baselines derived — every observation in the window was already decayed, "+
			"so there is no healthy state to calibrate against")
	}
	return out, warnings
}

// Apply fills in baselines for evidence rows that carry none.
//
// An explicit baseline in the evidence file always wins: a derived number is a
// convenience, and silently overriding a figure an operator wrote by hand would
// make the score untraceable to its input.
func Apply(evs []score.Evidence, f File, now time.Time) ([]score.Evidence, []string) {
	var warnings []string
	age := 0
	if t, err := time.Parse(time.RFC3339, f.GeneratedAt); err == nil {
		if d := now.Sub(t); d > 0 {
			age = int(d.Seconds())
		}
	}

	missing := 0
	out := make([]score.Evidence, len(evs))
	copy(out, evs)
	for i := range out {
		if out[i].BaselineVolume != 0 {
			continue // explicit beats derived
		}
		b, ok := f.Baselines[Key(out[i].Rule, out[i].State)]
		if !ok {
			missing++
			continue
		}
		out[i].BaselineVolume = b.Volume
		if out[i].BaselineFieldPopulate == 0 {
			out[i].BaselineFieldPopulate = b.FieldPopulate
		}
		// Age flows into the confidence gate, not the score: an old baseline
		// makes a verdict less certain, it does not make decay worse.
		if out[i].BaselineAgeSeconds == 0 {
			out[i].BaselineAgeSeconds = age
		}
	}

	if missing > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d row(s) have no baseline and none could be derived — they will report INSUFFICIENT_DATA", missing))
	}
	return out, warnings
}
