//go:build windows

// internal/collector/usn/usn_test.go
package usn

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "usn" {
		t.Fatalf("Name = %q, want usn", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta
// la forma del contrato (skip si el journal no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("USN no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "usn" {
			t.Fatalf("Type = %q, want usn", a.Type)
		}
	}
}
