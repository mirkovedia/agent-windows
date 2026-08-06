//go:build windows

// internal/winfs/ntfs/ntfs_windows_test.go
package ntfs

import (
	"context"
	"testing"
)

// TestScanDeletedIntegration corre solo con acceso raw al volumen (elevación).
// No es determinista: valida forma, no contenido.
func TestScanDeletedIntegration(t *testing.T) {
	// Se verifica de paso que el avance sea monótono y acotado: un progreso
	// que retrocede o pasa del total haría saltar la barra de la interfaz.
	var lastDone, seenTotal int64
	onProgress := func(done, total int64) {
		if done < lastDone {
			t.Errorf("el avance retrocedió: %d después de %d", done, lastDone)
		}
		if total > 0 && done > total {
			t.Errorf("el avance pasó del total: %d/%d", done, total)
		}
		lastDone, seenTotal = done, total
	}

	entries, err := ScanDeleted(context.Background(), `\\.\C:`, onProgress)
	if err != nil {
		t.Skipf("MFT raw no accesible (¿sin elevación o volumen no NTFS?): %v", err)
	}
	if seenTotal == 0 {
		t.Error("el escaneo debería informar el total de la MFT")
	}
	for _, e := range entries {
		if e.FileName == "" {
			t.Fatalf("entry sin FileName: %+v", e)
		}
		if e.FullPath == "" {
			t.Fatalf("entry sin FullPath: %+v", e)
		}
	}
}

func TestErrUnsupportedDefined(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported no debería ser nil")
	}
}
