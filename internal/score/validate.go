package score

import (
	"fmt"
	"strings"
)

// ValidationError reports one problem with one evidence row.
type ValidationError struct {
	Index int    // 0-based position in the evidence file
	Rule  string // rule name if known, for a human-locatable message
	Field string // the offending JSON key
	Msg   string
}

func (e ValidationError) Error() string {
	where := fmt.Sprintf("row %d", e.Index)
	if e.Rule != "" {
		where = fmt.Sprintf("row %d (%s)", e.Index, e.Rule)
	}
	return fmt.Sprintf("%s: %q %s", where, e.Field, e.Msg)
}

// Validate checks evidence rows before scoring and returns every problem found,
// not just the first — a collector emitting a malformed file usually emits the
// same mistake on every row, and reporting them one run at a time is miserable.
//
// This exists because the scorer's failure mode is silent and confident. An
// omitted "liveness" key used to decode as "", fail the active check, and report
// DEAD:SOURCE "agent disconnected" for a row that never mentioned an agent; a
// mistyped "volume" key defaulted to 0 and reported a total source outage. Both
// are indistinguishable from a real incident in the output.
func Validate(evs []Evidence) []error {
	var errs []error

	add := func(i int, ev Evidence, field, msg string) {
		errs = append(errs, ValidationError{Index: i, Rule: ev.Rule, Field: field, Msg: msg})
	}

	for i, ev := range evs {
		if strings.TrimSpace(ev.Rule) == "" {
			add(i, ev, "rule", "is required")
		}

		// A row carrying a probe error measured nothing, so the measurement
		// fields are meaningless and are not checked.
		if ev.ProbeError != "" {
			continue
		}

		if strings.TrimSpace(ev.Liveness) == "" {
			add(i, ev, "liveness", `is required — omitting it would silently report DEAD:SOURCE (use "active" if the agent is connected)`)
		}
		if ev.Volume < 0 {
			add(i, ev, "volume", fmt.Sprintf("is negative (%d)", ev.Volume))
		}
		if ev.BaselineVolume < 0 {
			add(i, ev, "baseline_volume", fmt.Sprintf("is negative (%d)", ev.BaselineVolume))
		}
		if ev.FieldPopulate != nil {
			if fp := *ev.FieldPopulate; fp < 0 || fp > 1 {
				add(i, ev, "field_populate", fmt.Sprintf("is %.4f — must be a rate in [0,1], not a percentage or a count", fp))
			}
		}
		if bfp := ev.BaselineFieldPopulate; bfp < 0 || bfp > 1 {
			add(i, ev, "baseline_field_populate", fmt.Sprintf("is %.4f — must be a rate in [0,1], not a percentage or a count", bfp))
		}
	}
	return errs
}
