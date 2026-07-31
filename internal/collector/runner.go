package collector

import (
	"context"
	"fmt"
	"sort"
)

// Result es el resultado de ejecutar un Collector.
type Result struct {
	Collector string
	Artifacts []Artifact
	Err       error
}

// Observer recibe el avance del escaneo. Cualquiera de sus campos puede ser
// nil: existe para que una interfaz muestre progreso en vivo sin que los
// colectores sepan que hay una interfaz.
type Observer struct {
	// OnStart se invoca antes de correr cada colector. index es 1-based.
	OnStart func(index, total int, name string)
	// OnFinish se invoca al terminar cada colector, con su resultado (que
	// puede traer Err: un colector caído también se reporta).
	OnFinish func(index, total int, res Result)
}

// Run ejecuta los colectores ordenados por prioridad ascendente. Un panic
// dentro de un colector se recupera y se traduce a Result.Err: un colector
// que falla nunca tumba el escaneo.
func Run(ctx context.Context, collectors []Collector) []Result {
	return RunObserved(ctx, collectors, Observer{})
}

// RunObserved es Run con notificaciones de avance.
func RunObserved(ctx context.Context, collectors []Collector, obs Observer) []Result {
	ordered := make([]Collector, len(collectors))
	copy(ordered, collectors)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority() < ordered[j].Priority()
	})

	total := len(ordered)
	results := make([]Result, 0, total)
	for i, c := range ordered {
		index := i + 1
		if obs.OnStart != nil {
			obs.OnStart(index, total, c.Name())
		}
		res := runOne(ctx, c)
		if obs.OnFinish != nil {
			obs.OnFinish(index, total, res)
		}
		results = append(results, res)
	}
	return results
}

func runOne(ctx context.Context, c Collector) (res Result) {
	res.Collector = c.Name()
	defer func() {
		if r := recover(); r != nil {
			res.Err = fmt.Errorf("panic en colector %s: %v", c.Name(), r)
		}
	}()
	res.Artifacts, res.Err = c.Collect(ctx)
	return res
}
