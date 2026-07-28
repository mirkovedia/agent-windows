package bam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

func TestParseBAMFromFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "system_bam.hve"))
	if err != nil {
		t.Skipf("fixture ausente: %v", err)
	}
	h, err := reghive.Open(b)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	entries, err := parseBAM(h)
	if err != nil {
		t.Fatalf("parseBAM error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("esperaba al menos una entrada BAM en el fixture")
	}
	for _, e := range entries {
		if e.ExecutablePath == "" || e.SID == "" {
			t.Fatalf("entrada incompleta: %+v", e)
		}
	}
}

func TestDecodeBAMValueExtractsFiletime(t *testing.T) {
	// 8 bytes de FILETIME + relleno; se valida que no sea el cero epoch.
	raw := make([]byte, 24)
	// FILETIME correspondiente a un instante > 1601.
	for i, v := range []byte{0x00, 0x80, 0x3e, 0xd5, 0xde, 0xb1, 0x9d, 0x01} {
		raw[i] = v
	}
	ts, ok := decodeBAMValue(raw)
	if !ok {
		t.Fatal("esperaba decodificación válida")
	}
	if ts.IsZero() {
		t.Fatal("timestamp no debería ser cero")
	}
}
