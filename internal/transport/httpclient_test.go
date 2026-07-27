package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/report"
)

func TestOpenSessionReturnsNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions" || r.Method != http.MethodPost {
			t.Errorf("request inesperado: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionId": "sess-1", "nonce": "n-123"})
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	sess, err := up.OpenSession(context.Background(), OpenRequest{
		AgentVersion: "0.1.0", Pubkey: "abcd", ConsentAt: time.Now(), MachineInfoHash: "h",
	})
	if err != nil {
		t.Fatalf("OpenSession error: %v", err)
	}
	if sess.SessionID != "sess-1" || sess.Nonce != "n-123" {
		t.Fatalf("session = %+v", sess)
	}
}

func TestStreamFindingPostsToSession(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	err := up.StreamFinding(context.Background(), "sess-1", 0, report.Finding{ID: "f1"}, "hash")
	if err != nil {
		t.Fatalf("StreamFinding error: %v", err)
	}
	if gotPath != "/api/v1/sessions/sess-1/findings" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestOpenSessionRetriesThenFails(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	up.retryBackoff = time.Millisecond // acelerar el test
	_, err := up.OpenSession(context.Background(), OpenRequest{AgentVersion: "0.1.0"})
	if err == nil {
		t.Fatal("esperaba error tras agotar reintentos")
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3 (máx reintentos)", calls)
	}
}
