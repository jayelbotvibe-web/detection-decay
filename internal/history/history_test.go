package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Dir: t.TempDir()}
}

func TestSaveAndLoadRun(t *testing.T) {
	s := newStore(t)
	id := s.NewID(time.Date(2026, 8, 24, 16, 45, 0, 0, time.UTC))
	if id != "20260824T164500Z" {
		t.Fatalf("id = %q", id)
	}

	path, err := s.Save(id, []byte(`{"version":"v0.2.0"}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if want := filepath.Join(s.Dir, "runs", id, "decay.json"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	got, err := s.LoadRun(id)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if string(got) != `{"version":"v0.2.0"}` {
		t.Errorf("round-trip mismatch: %s", got)
	}
}

// TestNewIDNeverOverwrites: two runs in the same second must not collide, or
// the first one's artifact is silently destroyed.
func TestNewIDNeverOverwrites(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 8, 24, 16, 45, 0, 0, time.UTC)

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		id := s.NewID(at)
		if seen[id] {
			t.Fatalf("NewID returned %q twice", id)
		}
		seen[id] = true
		if _, err := s.Save(id, []byte(`{}`)); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 distinct ids, got %d", len(seen))
	}
}

// TestRejectsTraversalID: run ids reach the store from a filesystem listing and
// later from an HTTP path, so they must never escape the run directory.
func TestRejectsTraversalID(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{"../escape", "a/b", "..", "with space", ""} {
		if _, err := s.Save(bad, []byte(`{}`)); err == nil {
			t.Errorf("Save(%q) should have been rejected", bad)
		}
		if _, err := s.LoadRun(bad); err == nil {
			t.Errorf("LoadRun(%q) should have been rejected", bad)
		}
	}
}

func TestAppendAndLatest(t *testing.T) {
	s := newStore(t)

	if latest, err := s.Latest(); err != nil || latest != nil {
		t.Fatalf("empty store: latest=%v err=%v", latest, err)
	}

	for _, id := range []string{"20260824T100000Z", "20260824T110000Z", "20260824T120000Z"} {
		if err := s.Append(Entry{ID: id, WorstVerdict: "HEALTHY"}); err != nil {
			t.Fatalf("Append(%s): %v", id, err)
		}
	}

	entries, err := s.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].ID > entries[2].ID {
		t.Error("entries should be oldest-first")
	}

	latest, err := s.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.ID != "20260824T120000Z" {
		t.Errorf("latest = %s", latest.ID)
	}
}

// TestCorruptIndexIsNotFatal: losing the trend history is not a reason to stop
// scoring, and refusing to run until someone hand-repairs a JSON file is the
// wrong trade for a monitoring tool.
func TestCorruptIndexIsNotFatal(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "history.json"), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Entries reports the problem...
	_, err := s.Entries()
	if err == nil {
		t.Fatal("Entries should report a corrupt index")
	}
	if !strings.Contains(err.Error(), "rebuilt") {
		t.Errorf("error should say the index will be rebuilt, got %q", err)
	}

	// ...and Append recovers from it rather than propagating the failure.
	if err := s.Append(Entry{ID: "20260824T120000Z"}); err != nil {
		t.Fatalf("Append should rebuild a corrupt index, got %v", err)
	}
	entries, err := s.Entries()
	if err != nil {
		t.Fatalf("index still unreadable after rebuild: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after rebuild, got %d", len(entries))
	}
}

func TestIndexIsValidJSON(t *testing.T) {
	s := newStore(t)
	if err := s.Append(Entry{
		ID: "20260824T120000Z", GeneratedAt: "2026-08-24T12:00:00Z", Evidence: "e.json",
		Evaluated: 6, Healthy: 1, Silent: 4, Unknown: 1,
		WorstDecay: 1.0, WorstVerdict: "DEAD:SOURCE",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("index is not valid JSON: %v", err)
	}
	if entries[0].WorstDecay != 1.0 || entries[0].Unknown != 1 {
		t.Errorf("index lost numbers: %+v", entries[0])
	}
}

// TestAppendLeavesNoTempFiles guards the atomic write: an interrupted run must
// not leave a half-written index, and a successful one must not litter.
func TestAppendLeavesNoTempFiles(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 3; i++ {
		if err := s.Append(Entry{ID: "20260824T12000" + string(rune('0'+i)) + "Z"}); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".history-") {
			t.Errorf("left a temp file behind: %s", f.Name())
		}
	}
}
