// internal/collector/services/services_test.go
package services

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New(`C:\Windows\System32\config\SYSTEM`)
	if c.Name() != "services" {
		t.Fatalf("Name = %q, want services", c.Name())
	}
	if c.Priority() != collector.PriorityRegistry {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityRegistry)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New(`C:\Windows\System32\config\SYSTEM`)
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea contra el
// hive real; hace skip si no hay acceso (hive bloqueado sin VSS, o no-Windows).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New(`C:\Windows\System32\config\SYSTEM`).Collect(context.Background())
	if err != nil {
		t.Skipf("hive SYSTEM no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "service_driver" {
			t.Fatalf("Type = %q, want service_driver", a.Type)
		}
	}
}
