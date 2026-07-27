package collector

import (
	"context"
	"errors"
	"testing"
)

type stubCollector struct {
	name     string
	priority int
	panics   bool
	err      error
}

func (s stubCollector) Name() string  { return s.name }
func (s stubCollector) Priority() int { return s.priority }
func (s stubCollector) Collect(ctx context.Context) ([]Artifact, error) {
	if s.panics {
		panic("boom")
	}
	if s.err != nil {
		return nil, s.err
	}
	return []Artifact{{Type: s.name}}, nil
}

func TestRunOrdersByPriority(t *testing.T) {
	cols := []Collector{
		stubCollector{name: "disk", priority: PriorityDisk},
		stubCollector{name: "volatile", priority: PriorityVolatile},
		stubCollector{name: "registry", priority: PriorityRegistry},
	}
	results := Run(context.Background(), cols)
	got := []string{results[0].Collector, results[1].Collector, results[2].Collector}
	want := []string{"volatile", "registry", "disk"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden = %v, want %v", got, want)
		}
	}
}

func TestRunRecoversPanic(t *testing.T) {
	cols := []Collector{stubCollector{name: "bad", priority: PriorityVolatile, panics: true}}
	results := Run(context.Background(), cols)
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("esperaba Err no nil tras panic recuperado")
	}
}

func TestRunPropagatesCollectorError(t *testing.T) {
	sentinel := errors.New("falla de disco")
	cols := []Collector{stubCollector{name: "x", priority: PriorityVolatile, err: sentinel}}
	results := Run(context.Background(), cols)
	if !errors.Is(results[0].Err, sentinel) {
		t.Fatalf("Err = %v, want %v", results[0].Err, sentinel)
	}
}
