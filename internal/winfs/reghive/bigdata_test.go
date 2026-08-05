package reghive

import (
	"bytes"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive/reghivetest"
)

// TestValueReassemblesBigData cubre la causa raíz del fallo de shimcache en
// una máquina real: AppCompatCache pesa cientos de KB, así que Windows lo
// guarda segmentado detrás de una celda "db". Sin rearmar los segmentos, el
// llamador recibe el descriptor ("db" + conteo + offset) y lo interpreta como
// si fueran los datos. Ese es el 0x126264 que reportó el escaneo: "db" con 18
// segmentos, leído como si fuera la firma del AppCompatCache.
func TestValueReassemblesBigData(t *testing.T) {
	// Más grande que un segmento, para forzar varios.
	data := make([]byte, reghivetest.MaxSegmentData*2+1234)
	for i := range data {
		data[i] = byte(i % 251)
	}

	b := reghivetest.NewBuilder()
	val := b.AddBigValue("Grande", data, 3)
	root := b.AddKey("Root", nil, []uint32{val})

	h, err := Open(b.Build(root))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key, err := h.OpenKey("")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	got, _, err := key.Value("Grande")
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("largo = %d, want %d", len(got), len(data))
	}
	if !bytes.Equal(got, data) {
		t.Fatal("los datos rearmados no coinciden con los originales")
	}
}

// TestValueSmallDataStillWorks protege el camino normal: la inmensa mayoría de
// los valores entra en una sola celda y no debe pasar por el rearmado.
func TestValueSmallDataStillWorks(t *testing.T) {
	data := []byte("un valor corto y comun")

	b := reghivetest.NewBuilder()
	val := b.AddValue("Chico", data, 1)
	root := b.AddKey("Root", nil, []uint32{val})

	h, err := Open(b.Build(root))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key, _ := h.OpenKey("")
	got, _, err := key.Value("Chico")
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q, want %q", got, data)
	}
}
