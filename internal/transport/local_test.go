package transport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telagem/agent-windows/internal/report"
)

func TestLocalUploaderImplementsUploader(t *testing.T) {
	var _ Uploader = NewLocalUploader("x.json")
}

func TestLocalUploaderOpenSessionIsOffline(t *testing.T) {
	u := NewLocalUploader(filepath.Join(t.TempDir(), "r.json"))
	s, err := u.OpenSession(context.Background(), OpenRequest{AgentVersion: "0.1.0"})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if s.SessionID == "" {
		t.Fatal("SessionID vacío")
	}
	if s.Nonce == "" {
		t.Fatal("Nonce vacío: la cadena de hash lo necesita como salt")
	}
}

func TestLocalUploaderTwoSessionsDifferentNonce(t *testing.T) {
	u := NewLocalUploader(filepath.Join(t.TempDir(), "r.json"))
	a, _ := u.OpenSession(context.Background(), OpenRequest{})
	b, _ := u.OpenSession(context.Background(), OpenRequest{})
	if a.Nonce == b.Nonce {
		t.Fatal("dos sesiones no deberían compartir nonce")
	}
}

func TestLocalUploaderCompleteWritesReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reporte.json")
	u := NewLocalUploader(path)
	rep := report.Report{
		SessionID: "sess-1",
		Platform:  "windows",
		Status:    "COMPLETE",
		Findings:  []report.Finding{{ID: "f1", Title: "algo", Severity: "INFO"}},
	}

	out, err := u.Complete(context.Background(), "sess-1", rep, "deadbeef", "root123")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out != path {
		t.Fatalf("Complete devolvió %q, esperaba la ruta del archivo %q", out, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no se escribió el reporte: %v", err)
	}
	var got report.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("el reporte no es JSON válido: %v", err)
	}
	if got.SessionID != "sess-1" || len(got.Findings) != 1 {
		t.Fatalf("reporte inesperado: %+v", got)
	}
	if got.Signature != "deadbeef" {
		t.Fatalf("la firma debe quedar en el archivo, obtuve %q", got.Signature)
	}
}

func TestLocalUploaderStreamAndHeartbeatAreNoops(t *testing.T) {
	u := NewLocalUploader(filepath.Join(t.TempDir(), "r.json"))
	if err := u.StreamFinding(context.Background(), "s", 0, report.Finding{}, "h"); err != nil {
		t.Fatalf("StreamFinding debería ser no-op: %v", err)
	}
	if err := u.Heartbeat(context.Background(), "s", 0); err != nil {
		t.Fatalf("Heartbeat debería ser no-op: %v", err)
	}
}

func TestLocalUploaderCompleteFailsOnBadPath(t *testing.T) {
	u := NewLocalUploader(filepath.Join(t.TempDir(), "no-existe", "r.json"))
	if _, err := u.Complete(context.Background(), "s", report.Report{}, "sig", "root"); err == nil {
		t.Fatal("esperaba error si el directorio destino no existe")
	}
}
