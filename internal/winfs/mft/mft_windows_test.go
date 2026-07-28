//go:build windows

package mft

import (
	"context"
	"errors"
	"testing"
)

// TestScanTimestompIntegration corre solo con acceso al volumen (elevación).
// No es determinista: valida forma, no contenido.
func TestScanTimestompIntegration(t *testing.T) {
	findings, err := ScanTimestomp(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("MFT no accesible (¿sin elevación o FSCTL no soportado?): %v", err)
	}
	for _, f := range findings {
		if f.FullPath == "" {
			t.Fatalf("finding sin FullPath: %+v", f)
		}
		if !f.Verdict.Stomped {
			t.Fatalf("finding emitido sin Stomped: %+v", f)
		}
	}
}

func TestErrUnsupportedIsDefined(t *testing.T) {
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("ErrUnsupported mal definido")
	}
}
