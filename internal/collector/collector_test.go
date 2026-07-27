package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type fakeCollector struct {
	name     string
	priority int
}

func (f fakeCollector) Name() string  { return f.name }
func (f fakeCollector) Priority() int { return f.priority }
func (f fakeCollector) Collect(ctx context.Context) ([]Artifact, error) {
	return []Artifact{{
		Type:      "fake",
		Source:    "memory",
		Data:      json.RawMessage(`{"ok":true}`),
		Collected: time.Now(),
	}}, nil
}

func TestCollectorInterfaceSatisfied(t *testing.T) {
	var c Collector = fakeCollector{name: "fake", priority: PriorityVolatile}
	if c.Name() != "fake" {
		t.Fatalf("Name() = %q, want %q", c.Name(), "fake")
	}
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if len(arts) != 1 || arts[0].Type != "fake" {
		t.Fatalf("Collect() = %+v, want 1 artifact of type fake", arts)
	}
}

func TestPriorityConstantsOrdered(t *testing.T) {
	if !(PriorityVolatile < PriorityRegistry && PriorityRegistry < PriorityDisk) {
		t.Fatalf("orden de prioridad inválido: volatile=%d registry=%d disk=%d",
			PriorityVolatile, PriorityRegistry, PriorityDisk)
	}
}
