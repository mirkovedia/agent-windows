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

// Reporter lo implementan los colectores capaces de informar su avance
// interno. Es opcional a propósito: solo vale la pena en los que tardan
// (recorrer la MFT entera lleva decenas de segundos), y así los otros no se
// tocan. El runner lo detecta con un type assertion.
//
// done y total están en la unidad que cada colector considere natural —bytes
// de MFT, archivos, registros— porque lo único que necesita la interfaz es la
// proporción. total puede ser 0 si el colector todavía no sabe cuánto falta.
type Reporter interface {
	SetProgress(fn func(done, total int64))
}
