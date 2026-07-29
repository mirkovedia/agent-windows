//go:build windows

// internal/collector/deleted/deleted_test.go
package deleted

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "deleted_entries" {
		t.Fatalf("Name = %q, want deleted_entries", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta la
// forma del contrato (skip si el volumen raw no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("MFT raw no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "deleted_entry" {
			t.Fatalf("Type = %q, want deleted_entry", a.Type)
		}
	}
}
