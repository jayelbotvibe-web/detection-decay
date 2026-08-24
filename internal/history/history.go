// Package history persists scoring runs and indexes them for trend reading.
//
// Decay is a measurement over time: a single run says a rule looks dead, a
// series says when it died. Storage is plain JSON files rather than a database,
// which keeps the binary dependency-free and the artifacts greppable.
//
// The layout mirrors purple-loop's reporter: an immutable per-run artifact plus
// a slim index. Fingerprints deliberately live in the run artifact, not the
// index, so the index stays small enough to read every run.
//
//	<dir>/runs/<id>/decay.json   full report, never rewritten
//	<dir>/history.json           trend index, one Entry per trusted run
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IDFormat is the run-id timestamp layout: 20260824T164500Z.
const IDFormat = "20060102T150405Z"

// idPattern is the first of two guards on a run id. It is not sufficient on its
// own: "." and ".." both match it, which is how a pattern-only check lets an id
// escape the runs directory. runDir performs the containment check that actually
// holds, so a future widening of this pattern cannot reintroduce traversal.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// runDir resolves the directory for a run id, refusing anything that would land
// outside <Dir>/runs.
func (s *Store) runDir(id string) (string, error) {
	if id == "." || id == ".." || !idPattern.MatchString(id) {
		return "", fmt.Errorf("invalid run id %q", id)
	}
	root := filepath.Join(s.Dir, "runs")
	dir := filepath.Join(root, id)
	// Containment is verified after joining, so the guarantee does not rest on
	// the pattern enumerating every dangerous form.
	if dir != root && !strings.HasPrefix(dir, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("run id %q escapes the run directory", id)
	}
	if dir == root {
		return "", fmt.Errorf("invalid run id %q", id)
	}
	return dir, nil
}

// Entry is one row in the trend index. It carries the numbers, never the prose
// that describes them — a consumer should not have to re-parse an explanation
// to recover a score.
type Entry struct {
	ID           string  `json:"id"`
	GeneratedAt  string  `json:"generated_at"`
	Evidence     string  `json:"evidence"`
	Evaluated    int     `json:"evaluated"`
	Healthy      int     `json:"healthy"`
	Silent       int     `json:"silent"`
	Unknown      int     `json:"unknown"`
	WorstDecay   float64 `json:"worst_decay"`
	WorstVerdict string  `json:"worst_verdict"`
}

// Store is a run directory.
type Store struct {
	Dir string
}

// NewID returns a run id for t, unique within the store: a second run in the
// same second gets a -2 suffix rather than overwriting the first.
func (s *Store) NewID(t time.Time) string {
	base := t.UTC().Format(IDFormat)
	id := base
	for n := 2; ; n++ {
		dir, err := s.runDir(id)
		if err != nil {
			return base // generated ids are always well-formed
		}
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
}

func (s *Store) indexPath() string { return filepath.Join(s.Dir, "history.json") }

// Save writes the run artifact and returns its path. It is written whether or
// not the run is trustworthy enough to index — a failed run is exactly what you
// want to look at afterwards.
func (s *Store) Save(id string, report []byte) (string, error) {
	dir, err := s.runDir(id)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create run dir: %w", err)
	}
	path := filepath.Join(dir, "decay.json")
	if err := os.WriteFile(path, report, 0o644); err != nil {
		return "", fmt.Errorf("write run: %w", err)
	}
	return path, nil
}

// LoadRun reads a run artifact. The caller unmarshals it — the report shape
// belongs to the command, not to storage.
func (s *Store) LoadRun(id string) ([]byte, error) {
	dir, err := s.runDir(id)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dir, "decay.json"))
}

// Entries returns the index oldest-first.
//
// A corrupt or truncated index is reported but never fatal: losing the trend
// history is not a reason to stop scoring, and refusing to run until someone
// hand-repairs a JSON file is the wrong trade for a monitoring tool.
func (s *Store) Entries() ([]Entry, error) {
	data, err := os.ReadFile(s.indexPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("index at %s is unreadable (%v) — it will be rebuilt from this run on", s.indexPath(), err)
	}
	sort.SliceStable(entries, func(i, j int) bool { return lessID(entries[i].ID, entries[j].ID) })
	return entries, nil
}

// splitID separates a run id into its timestamp and its collision suffix:
// "20260824T164500Z-10" becomes ("20260824T164500Z", 10). An id with no suffix
// is ordinal 1, since it is the first run of that second.
func splitID(id string) (string, int) {
	i := strings.LastIndex(id, "-")
	if i < 0 {
		return id, 1
	}
	n, err := strconv.Atoi(id[i+1:])
	if err != nil || n < 2 {
		return id, 1
	}
	return id[:i], n
}

// lessID orders run ids chronologically.
//
// A plain string comparison is wrong: suffixes run -2, -3 ... -10, -11, and
// lexicographically "Z-10" sorts before "Z-2". That silently mis-orders the
// index once ten runs land in the same second, so Latest returns the wrong run
// and the run-over-run diff compares against the wrong baseline.
func lessID(a, b string) bool {
	ab, an := splitID(a)
	bb, bn := splitID(b)
	if ab != bb {
		return ab < bb // timestamps sort correctly as strings
	}
	return an < bn
}

// Latest returns the most recently indexed run, or nil if there is none.
func (s *Store) Latest() (*Entry, error) {
	entries, err := s.Entries()
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return &entries[len(entries)-1], nil
}

// Append adds an entry to the index, rebuilding it if it was unreadable.
func (s *Store) Append(e Entry) error {
	entries, err := s.Entries()
	if err != nil {
		entries = nil // rebuild rather than refuse
	}
	entries = append(entries, e)

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode index: %w", err)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}

	// Write via a temp file in the same directory so an interrupted run cannot
	// leave a half-written index behind — the failure this tolerates above.
	tmp, err := os.CreateTemp(s.Dir, ".history-*.json")
	if err != nil {
		return fmt.Errorf("create temp index: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp index: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp index: %w", err)
	}
	if err := os.Rename(tmpName, s.indexPath()); err != nil {
		return fmt.Errorf("replace index: %w", err)
	}
	return nil
}

// RunIDs lists every run artifact on disk, oldest first — including runs that
// were never indexed because they measured nothing.
//
// The index deliberately excludes untrustworthy runs, which means the newest
// indexed run can be hours older than the newest attempt. A caller showing the
// latest indexed run needs to know that, or it displays a stale healthy board
// while every probe since has been failing — the same false reassurance this
// tool exists to prevent.
func (s *Store) RunIDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "runs"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runs: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := s.runDir(e.Name()); err != nil {
			continue // not a run id we would ever have written
		}
		ids = append(ids, e.Name())
	}
	sort.SliceStable(ids, func(i, j int) bool { return lessID(ids[i], ids[j]) })
	return ids, nil
}

// LatestRunID returns the newest run artifact on disk, indexed or not.
func (s *Store) LatestRunID() (string, error) {
	ids, err := s.RunIDs()
	if err != nil || len(ids) == 0 {
		return "", err
	}
	return ids[len(ids)-1], nil
}
