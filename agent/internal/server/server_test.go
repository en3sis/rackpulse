package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/en3sis/rackpulse/agent/internal/pairing"
)

func TestRoutingAndAuth(t *testing.T) {
	h := &handler{version: "0.2.0", token: "rb1_" + strings.Repeat("k", 43), fingerprint: "cd"}
	nonce := strings.Repeat("ab", 32)
	cases := []struct {
		method, path, key string
		status            int
	}{
		{http.MethodGet, "/nope", "", http.StatusNotFound},
		{http.MethodPost, "/v1/hello?nonce=" + nonce, "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/hello?nonce=ab", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/history", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/snapshot", "rb1_wrong", http.StatusUnauthorized},
		{http.MethodGet, "/v1/security", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/security", "rb1_wrong", http.StatusUnauthorized},
		{http.MethodPost, "/v1/security", h.token, http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		request := httptest.NewRequest(c.method, c.path, nil)
		if c.key != "" {
			request.Header.Set("Authorization", "Bearer "+c.key)
		}
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, request)
		if recorder.Code != c.status {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, recorder.Code, c.status)
		}
	}

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/hello?nonce="+nonce, nil))
	var hello map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &hello); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("hello %d %s", recorder.Code, recorder.Body)
	}
	if hello["agent"] != "rackpulse-agent" || hello["version"] != "0.2.0" || hello["proof"] != pairing.Proof(h.token, nonce, "cd") {
		t.Fatalf("hello %v", hello)
	}
}
