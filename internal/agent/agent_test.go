package agent

import (
	"context"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
)

type fakeUploader struct {
	findings  int
	completed bool
}

func (f *fakeUploader) OpenSession(ctx context.Context, req transport.OpenRequest) (transport.Session, error) {
	return transport.Session{SessionID: "s1", Nonce: "n1"}, nil
}
func (f *fakeUploader) StreamFinding(ctx context.Context, id string, seq int, fi report.Finding, ch string) error {
	f.findings++
	return nil
}
func (f *fakeUploader) Complete(ctx context.Context, id string, r report.Report, sig, root string) (string, error) {
	f.completed = true
	return "https://verify/s1", nil
}
func (f *fakeUploader) Heartbeat(ctx context.Context, id string, seq int) error { return nil }

func TestRunProducesSignedReport(t *testing.T) {
	up := &fakeUploader{}
	opts := Options{Timeout: time.Minute, ServerURL: "http://x", Version: "test"}
	rep, err := runWithCollectors(context.Background(), opts, up, testCollectors(), true)
	if err != nil {
		t.Fatalf("runWithCollectors error: %v", err)
	}
	if rep.Signature == "" {
		t.Fatal("el reporte debería estar firmado")
	}
	if rep.Status != "COMPLETE" {
		t.Fatalf("Status = %q, want COMPLETE", rep.Status)
	}
	if len(rep.HashChain) < 1 {
		t.Fatal("la cadena de hashes no debería estar vacía")
	}
	if !up.completed {
		t.Fatal("Complete no fue llamado")
	}
}

func TestRunAbortsWithoutConsent(t *testing.T) {
	up := &fakeUploader{}
	opts := Options{Timeout: time.Minute, Version: "test"}
	_, err := runWithCollectors(context.Background(), opts, up, testCollectors(), false)
	if err == nil {
		t.Fatal("esperaba error si no hay consentimiento")
	}
}
