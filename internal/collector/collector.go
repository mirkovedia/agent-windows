package collector

import (
	"context"
	"encoding/json"
	"time"
)

// Prioridades de ejecución: menor corre antes. Los colectores volátiles
// (procesos, memoria, red) van primero; los de disco después.
const (
	PriorityVolatile = 10
	PriorityRegistry = 40
	PriorityDisk     = 50
)

// Artifact es un dato forense estructurado producido por un Collector.
type Artifact struct {
	Type      string          `json:"type"`
	Source    string          `json:"source"`
	Data      json.RawMessage `json:"data"`
	Collected time.Time       `json:"collected"`
}

// Collector recolecta un tipo de artefacto de forma independiente.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Artifact, error)
	Priority() int
}
