// Package server exposes recorded runs over a read-only HTTP API.
//
// It is deliberately small: no writes, no auth, no mutation of any kind. The
// only thing it can do is show you runs that already exist on disk, which is
// why binding it beyond loopback is an explicit opt-in rather than a flag you
// might set by accident.
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/detection-decay/internal/history"
)

//go:embed web/index.html
var webFS embed.FS

// Server serves a run store.
type Server struct {
	Store *history.Store
	Mux   *http.ServeMux
}

// New wires the routes.
func New(store *history.Store) *Server {
	s := &Server{Store: store, Mux: http.NewServeMux()}

	s.Mux.HandleFunc("/", s.secure(get(s.handleIndex)))
	s.Mux.HandleFunc("/api/health", s.secure(get(s.handleHealth)))
	s.Mux.HandleFunc("/api/history", s.secure(get(s.handleHistory)))
	s.Mux.HandleFunc("/api/runs/", s.secure(get(s.handleRun)))

	return s
}

// get rejects anything but GET. The API is read-only by construction, and a
// handler that silently accepted POST would be a lie about that.
func get(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "this API is read-only")
			return
		}
		h(w, r)
	}
}

func (s *Server) secure(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// The page is self-contained: no external origin should ever be reached,
		// so anything trying to is a bug or an injection.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	page, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard is missing from the binary")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

// handleHealth reports only liveness. Operational numbers live behind /api,
// so an exposed health check cannot be used to survey the estate.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Store.Entries()
	if err != nil {
		// A corrupt index is not a server error — it is a fact about the store,
		// and the page should say so rather than show a blank trend.
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"entries": []history.Entry{},
			"warning": err.Error(),
		})
		return
	}
	if entries == nil {
		entries = []history.Entry{}
	}

	// The newest attempt is reported alongside the index because they can
	// diverge: a run that measured nothing is saved but never indexed. Without
	// this the page shows the last trusted run as though it were current, while
	// every probe since may have been failing.
	body := map[string]interface{}{"entries": entries}
	if latest, err := s.Store.LatestRunID(); err == nil && latest != "" {
		body["latest_attempt"] = latest
		indexed := ""
		if len(entries) > 0 {
			indexed = entries[len(entries)-1].ID
		}
		body["latest_attempt_indexed"] = latest == indexed
	}
	writeJSON(w, http.StatusOK, body)
}

// handleRun serves /api/runs/<id> and /api/runs/latest.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	if id == "" {
		writeError(w, http.StatusNotFound, "specify a run id, or 'latest'")
		return
	}

	if id == "latest" {
		latest, err := s.Store.Latest()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "history index is unreadable")
			return
		}
		if latest == nil {
			writeError(w, http.StatusNotFound, "no runs recorded yet")
			return
		}
		id = latest.ID
	}

	// Store.LoadRun validates the id and verifies path containment; the handler
	// deliberately does not attempt its own sanitising, so there is one place
	// that decides what a valid run id is.
	data, err := s.Store.LoadRun(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

// IsLoopback reports whether addr binds only to the local machine.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8788" binds every interface
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenAndServe starts the server with explicit timeouts.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

// Describe returns the startup banner.
func (s *Server) Describe(addr string) string {
	return fmt.Sprintf("decay dashboard on http://%s  (read-only, store: %s)", addr, s.Store.Dir)
}
