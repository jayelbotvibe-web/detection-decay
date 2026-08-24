package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/detection-decay/internal/history"
)

func newTestServer(t *testing.T) (*Server, *history.Store) {
	t.Helper()
	store := &history.Store{Dir: t.TempDir()}
	return New(store), store
}

func seed(t *testing.T, store *history.Store, id, body string) {
	t.Helper()
	if _, err := store.Save(id, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(history.Entry{ID: id, WorstVerdict: "HEALTHY", Evaluated: 1, Healthy: 1}); err != nil {
		t.Fatal(err)
	}
}

func do(s *Server, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestHealthIsLivenessOnly(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(s, http.MethodGet, "/api/health")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	// Operational numbers must not leak from a health check.
	for _, leak := range []string{"decay", "evaluated", "verdict", "runs"} {
		if strings.Contains(strings.ToLower(w.Body.String()), leak) {
			t.Errorf("health check leaked %q: %s", leak, w.Body.String())
		}
	}
}

// TestAPIIsReadOnly: the API cannot mutate anything, and a handler that
// silently accepted a write would be a lie about that.
func TestAPIIsReadOnly(t *testing.T) {
	s, store := newTestServer(t)
	seed(t, store, "20260824T164500Z", `{"summary":{}}`)

	for _, path := range []string{"/", "/api/health", "/api/history", "/api/runs/latest"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			w := do(s, method, path)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", method, path, w.Code)
			}
			if allow := w.Header().Get("Allow"); !strings.Contains(allow, "GET") {
				t.Errorf("%s %s: Allow header = %q", method, path, allow)
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(s, http.MethodGet, "/")
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	// The page is self-contained; nothing should ever reach another origin.
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP does not deny by default: %q", csp)
	}
}

func TestHistoryEmptyIsNotNull(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(s, http.MethodGet, "/api/history")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got struct {
		Entries []history.Entry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Entries == nil {
		t.Error("entries should marshal as [], not null — the page should not have to nil-check")
	}
}

// TestCorruptIndexIsReportedNotHidden: a broken index is a fact about the store,
// and the page must say so rather than render a blank trend that reads as "no
// decay recorded".
func TestCorruptIndexIsReportedNotHidden(t *testing.T) {
	s, store := newTestServer(t)
	seed(t, store, "20260824T164500Z", `{"summary":{}}`)
	if err := writeFile(store.Dir+"/history.json", "{ not json"); err != nil {
		t.Fatal(err)
	}

	w := do(s, http.MethodGet, "/api/history")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got struct {
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Warning == "" {
		t.Error("a corrupt index must surface a warning, not an empty trend")
	}
}

func TestRunEndpoints(t *testing.T) {
	s, store := newTestServer(t)

	if w := do(s, http.MethodGet, "/api/runs/latest"); w.Code != http.StatusNotFound {
		t.Errorf("latest with no runs = %d, want 404", w.Code)
	}

	seed(t, store, "20260824T164500Z", `{"summary":{"worst_verdict":"DEAD:FIELD"}}`)
	seed(t, store, "20260824T164600Z", `{"summary":{"worst_verdict":"HEALTHY"}}`)

	w := do(s, http.MethodGet, "/api/runs/latest")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "HEALTHY") {
		t.Errorf("latest = %d %s", w.Code, w.Body.String())
	}

	w = do(s, http.MethodGet, "/api/runs/20260824T164500Z")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DEAD:FIELD") {
		t.Errorf("by id = %d %s", w.Code, w.Body.String())
	}

	if w := do(s, http.MethodGet, "/api/runs/nosuchrun"); w.Code != http.StatusNotFound {
		t.Errorf("unknown run = %d, want 404", w.Code)
	}
	if w := do(s, http.MethodGet, "/api/runs/"); w.Code != http.StatusNotFound {
		t.Errorf("bare /api/runs/ = %d, want 404", w.Code)
	}
}

// TestTraversalRejected covers the encoded forms that survive ServeMux path
// cleaning and actually reach the handler. The handler does no sanitising of its
// own — the store owns that decision — so this asserts the chain, not a regex.
func TestTraversalRejected(t *testing.T) {
	s, store := newTestServer(t)
	seed(t, store, "20260824T164500Z", `{"summary":{}}`)
	if err := writeFile(store.Dir+"/secret.json", `{"secret":"do-not-serve"}`); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/api/runs/%2e%2e",
		"/api/runs/..%2f..%2fsecret.json",
		"/api/runs/%2e%2e%2f%2e%2e%2fsecret.json",
		"/api/runs/.",
		"/api/runs/a%2fb",
	} {
		w := do(s, http.MethodGet, path)
		if w.Code == http.StatusOK {
			t.Errorf("%s returned 200: %s", path, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "do-not-serve") {
			t.Errorf("%s leaked file content", path)
		}
	}
}

func TestIndexOnlyServesRoot(t *testing.T) {
	s, _ := newTestServer(t)
	if w := do(s, http.MethodGet, "/"); w.Code != http.StatusOK ||
		!strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("root = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(s, http.MethodGet, "/anything-else"); w.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", w.Code)
	}
}

// TestEmbeddedPageIsPresent guards against the page being dropped from the
// binary by a bad embed directive — the server would still build and start.
func TestEmbeddedPageIsPresent(t *testing.T) {
	s, _ := newTestServer(t)
	body := do(s, http.MethodGet, "/").Body.String()
	for _, want := range []string{"<title>", "/api/history", "/api/runs/latest", "measured nothing"} {
		if !strings.Contains(body, want) {
			t.Errorf("embedded page is missing %q", want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8788": true,
		"localhost:8788": true,
		"[::1]:8788":     true,
		"0.0.0.0:8788":   false,
		":8788":          false, // binds every interface
		"192.168.1.5:80": false,
		"[::]:8788":      false,
		"garbage":        false,
	}
	for addr, want := range cases {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestStaleBoardIsFlagged: a run that measured nothing is saved but not indexed,
// so the newest attempt can be far newer than the newest trusted run. Showing
// the trusted one as though it were current is the stale-green-board failure
// this tool exists to catch.
func TestStaleBoardIsFlagged(t *testing.T) {
	s, store := newTestServer(t)
	seed(t, store, "20260824T164500Z", `{"summary":{"worst_verdict":"HEALTHY"}}`)

	// A later run saved but never indexed, as recordRun does when nothing measured.
	if _, err := store.Save("20260824T170000Z", []byte(`{"summary":{"worst_verdict":"PROBE_ERROR"}}`)); err != nil {
		t.Fatal(err)
	}

	var got struct {
		LatestAttempt  string `json:"latest_attempt"`
		AttemptIndexed *bool  `json:"latest_attempt_indexed"`
	}
	if err := json.Unmarshal(do(s, http.MethodGet, "/api/history").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.LatestAttempt != "20260824T170000Z" {
		t.Errorf("latest_attempt = %q, want the unindexed run", got.LatestAttempt)
	}
	if got.AttemptIndexed == nil || *got.AttemptIndexed {
		t.Error("an unindexed newest attempt must be reported as such, or the page shows a stale board as current")
	}
}

func TestLatestAttemptIndexedWhenHealthy(t *testing.T) {
	s, store := newTestServer(t)
	seed(t, store, "20260824T164500Z", `{"summary":{}}`)

	var got struct {
		AttemptIndexed *bool `json:"latest_attempt_indexed"`
	}
	if err := json.Unmarshal(do(s, http.MethodGet, "/api/history").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AttemptIndexed == nil || !*got.AttemptIndexed {
		t.Error("a normal run should report its latest attempt as indexed")
	}
}
