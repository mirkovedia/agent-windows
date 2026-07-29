//go:build windows

package mft

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "mft_timestomp" {
		t.Fatalf("Name = %q, want mft_timestomp", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta la
// forma del contrato (skip si el volumen no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("MFT no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "mft_timestomp" {
			t.Fatalf("Type = %q, want mft_timestomp", a.Type)
		}
	}
}
