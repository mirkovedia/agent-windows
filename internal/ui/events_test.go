package ui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEventJSONIncludesKind(t *testing.T) {
	e := Event{Kind: KindCollectorDone, Collector: "prefetch", Index: 3, Total: 11, Artifacts: 1247}
	raw, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("el evento debe ser JSON válido: %v", err)
	}
	if got["kind"] != KindCollectorDone {
		t.Fatalf("kind = %v", got["kind"])
	}
	if got["collector"] != "prefetch" {
		t.Fatalf("collector = %v", got["collector"])
	}
}

// TestEventJSONOmitsEmptyFields mantiene chico el payload que cruza a JS:
// un evento de progreso se emite 22 veces por escaneo.
func TestEventJSONOmitsEmptyFields(t *testing.T) {
	e := Event{Kind: KindScanError, Error: "algo falló"}
	raw, _ := e.JSON()
	if strings.Contains(raw, `"collector"`) {
		t.Fatalf("los campos vacíos no deben serializarse: %s", raw)
	}
}

func TestEventKindsAreDistinct(t *testing.T) {
	kinds := map[string]bool{
		KindCollectorStart: true, KindCollectorDone: true,
		KindScanDone: true, KindScanError: true,
	}
	if len(kinds) != 4 {
		t.Fatalf("los cuatro kinds deben ser distintos, got %d", len(kinds))
	}
}
