// internal/ui/events.go

// Package ui es la capa de presentación del agente: una ventana WebView2 con
// la interfaz embebida en el binario. La lógica forense no depende de este
// paquete — la UI solo consume eventos que el runner emite.
package ui

import (
	"encoding/json"

	"github.com/telagem/agent-windows/internal/report"
)

// Tipos de evento que el backend empuja a la interfaz.
const (
	KindCollectorStart = "collector_start"
	KindCollectorDone  = "collector_done"
	// KindFinding es un hallazgo mostrado mientras el escaneo corre. Su
	// severidad es PRELIMINAR: no incluye combos ni deduplicación, que
	// necesitan el escaneo terminado. La pantalla final es la autoritativa.
	KindFinding   = "finding"
	KindScanDone  = "scan_done"
	KindScanError = "scan_error"
)

// Event es lo que la UI recibe durante el ciclo de vida del escaneo.
// Un solo tipo para todo el ciclo mantiene el puente Go↔JS con una única
// forma que validar.
type Event struct {
	Kind      string `json:"kind"`
	Collector string `json:"collector,omitempty"`
	Index     int    `json:"index,omitempty"`
	Total     int    `json:"total,omitempty"`
	Artifacts int    `json:"artifacts,omitempty"`
	Error     string `json:"error,omitempty"`

	// Campos de KindFinding.
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Title    string `json:"title,omitempty"`
	Path     string `json:"path,omitempty"`

	Report *report.Report `json:"report,omitempty"`
}

// JSON serializa el evento para pasarlo a JavaScript.
func (e Event) JSON() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
