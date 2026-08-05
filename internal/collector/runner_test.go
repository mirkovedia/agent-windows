package collector

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

func TestRunObservedEmitsStartAndFinishInOrder(t *testing.T) {
	cols := []Collector{
		stubCollector{name: "uno", priority: PriorityVolatile},
		stubCollector{name: "dos", priority: PriorityDisk},
	}
	var seq []string
	obs := Observer{
		OnStart: func(index, total int, name string) {
			seq = append(seq, fmt.Sprintf("start:%d/%d:%s", index, total, name))
		},
		OnFinish: func(index, total int, res Result) {
			seq = append(seq, fmt.Sprintf("finish:%d/%d:%s", index, total, res.Collector))
		},
	}
	RunObserved(context.Background(), cols, obs)

	want := []string{
		"start:1/2:uno", "finish:1/2:uno",
		"start:2/2:dos", "finish:2/2:dos",
	}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("secuencia = %v, want %v", seq, want)
	}
}

// TestRunObservedWithNilCallbacksDoesNotPanic cubre el camino del modo
// consola, que pasa un Observer vacío.
func TestRunObservedWithNilCallbacksDoesNotPanic(t *testing.T) {
	cols := []Collector{stubCollector{name: "uno", priority: PriorityDisk}}
	res := RunObserved(context.Background(), cols, Observer{})
	if len(res) != 1 {
		t.Fatalf("esperaba 1 resultado, got %d", len(res))
	}
}

// TestRunObservedReportsFailureToObserver garantiza que la UI pueda pintar en
// ámbar un colector caído: el observer tiene que ver el error, no solo el
// resultado final.
func TestRunObservedReportsFailureToObserver(t *testing.T) {
	cols := []Collector{stubCollector{name: "malo", priority: PriorityDisk, err: errors.New("sin permiso")}}
	var gotErr error
	RunObserved(context.Background(), cols, Observer{
		OnFinish: func(index, total int, res Result) { gotErr = res.Err },
	})
	if gotErr == nil {
		t.Fatal("el observer debe recibir el error del colector")
	}
}

// reportingCollector implementa Reporter para probar el cableado del avance.
type reportingCollector struct {
	stubCollector
	report func(done, total int64)
}

func (r *reportingCollector) SetProgress(fn func(done, total int64)) { r.report = fn }

func (r *reportingCollector) Collect(ctx context.Context) ([]Artifact, error) {
	if r.report != nil {
		r.report(50, 100) // a mitad de camino
	}
	return []Artifact{{Type: r.name}}, nil
}

func TestRunObservedForwardsInternalProgress(t *testing.T) {
	c := &reportingCollector{stubCollector: stubCollector{name: "lento", priority: PriorityDisk}}
	var gotDone, gotTotal int64
	var gotIndex, gotOf int
	RunObserved(context.Background(), []Collector{c}, Observer{
		OnProgress: func(index, total int, name string, done, unitTotal int64) {
			gotIndex, gotOf, gotDone, gotTotal = index, total, done, unitTotal
		},
	})
	if gotDone != 50 || gotTotal != 100 {
		t.Fatalf("avance = %d/%d, want 50/100", gotDone, gotTotal)
	}
	if gotIndex != 1 || gotOf != 1 {
		t.Fatalf("posicion = %d/%d, want 1/1", gotIndex, gotOf)
	}
}

// TestRunObservedIgnoresNonReporters cubre a los 8 colectores que no
// implementan la interfaz: deben correr igual, sin cablear nada.
func TestRunObservedIgnoresNonReporters(t *testing.T) {
	cols := []Collector{stubCollector{name: "simple", priority: PriorityDisk}}
	called := false
	res := RunObserved(context.Background(), cols, Observer{
		OnProgress: func(int, int, string, int64, int64) { called = true },
	})
	if called {
		t.Fatal("un colector que no implementa Reporter no debe emitir avance")
	}
	if len(res) != 1 {
		t.Fatalf("esperaba 1 resultado, got %d", len(res))
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
