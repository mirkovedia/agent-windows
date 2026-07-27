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

// Run ejecuta los colectores ordenados por prioridad ascendente. Un panic
// dentro de un colector se recupera y se traduce a Result.Err: un colector
// que falla nunca tumba el escaneo.
func Run(ctx context.Context, collectors []Collector) []Result {
	ordered := make([]Collector, len(collectors))
	copy(ordered, collectors)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority() < ordered[j].Priority()
	})

	results := make([]Result, 0, len(ordered))
	for _, c := range ordered {
		results = append(results, runOne(ctx, c))
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
