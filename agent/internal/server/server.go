package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/history"
	"github.com/en3sis/rackpulse/agent/internal/pairing"
	"github.com/en3sis/rackpulse/agent/internal/security"
)

const failedAuthDelay = 750 * time.Millisecond

type handler struct {
	version     string
	token       string
	fingerprint string
	collector   *collect.Collector
	security    *security.Collector
	host        *history.Host
	containers  *history.Containers
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var serve func(http.ResponseWriter, *http.Request)
	needsKey := true
	switch r.URL.Path {
	case "/v1/hello":
		serve = h.hello
		needsKey = false
	case "/v1/snapshot":
		serve = h.snapshot
	case "/v1/security":
		serve = h.securityReport
	case "/v1/history":
		serve = h.hostHistory
	case "/v1/containers/history":
		serve = h.containerHistory
	default:
		writeError(w, http.StatusNotFound, "Not found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "Only GET is allowed")
		return
	}
	if needsKey && !h.authorized(r) {
		time.Sleep(failedAuthDelay)
		writeError(w, http.StatusUnauthorized, "Wrong or missing key")
		return
	}
	serve(w, r)
}

func (h *handler) authorized(r *http.Request) bool {
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.token)) == 1
}

func (h *handler) hello(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if !pairing.ValidNonce(nonce) {
		writeError(w, http.StatusBadRequest, "nonce must be 64 hex characters")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"agent":   "rackpulse-agent",
		"version": h.version,
		"proof":   pairing.Proof(h.token, nonce, h.fingerprint),
	})
}

func (h *handler) snapshot(w http.ResponseWriter, r *http.Request) {
	serveCached(w, r, h.collector.Ready(), h.collector.Latest, "The first sample is not ready yet")
}

func (h *handler) securityReport(w http.ResponseWriter, r *http.Request) {
	serveCached(w, r, h.security.Ready(), h.security.Latest, "The first security check is not ready yet")
}

func serveCached(w http.ResponseWriter, r *http.Request, ready <-chan struct{}, latest func() []byte, notReady string) {
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		writeError(w, http.StatusServiceUnavailable, notReady)
		return
	case <-r.Context().Done():
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(latest())
}

func parseSince(r *http.Request) (int64, bool) {
	value := r.URL.Query().Get("since")
	if value == "" {
		return 0, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed >= 0
}

func (h *handler) hostHistory(w http.ResponseWriter, r *http.Request) {
	since, ok := parseSince(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "since must be a Unix time in seconds")
		return
	}
	writeJSON(w, http.StatusOK, h.host.Query(since, time.Now().Unix()))
}

func (h *handler) containerHistory(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	since, ok := parseSince(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "since must be a Unix time in seconds")
		return
	}
	response, found := h.containers.Query(name, since, time.Now().Unix())
	if !found {
		writeError(w, http.StatusNotFound, "No container with this name in the last 7 days")
		return
	}
	writeJSON(w, http.StatusOK, response)
}
