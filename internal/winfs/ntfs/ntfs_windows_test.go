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
	entries, err := ScanDeleted(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("MFT raw no accesible (¿sin elevación o volumen no NTFS?): %v", err)
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
