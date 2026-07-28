//go:build windows

// internal/winfs/usn/usn_windows_test.go
package usn

import (
	"context"
	"errors"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
)

// TestReadJournalIntegration corre solo si hay acceso al journal (elevación).
// No es determinista: valida forma, no contenido.
func TestReadJournalIntegration(t *testing.T) {
	entries, err := ReadJournal(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("USN no accesible (¿sin elevación o journal inactivo?): %v", err)
	}
	for _, e := range entries {
		if e.FullPath == "" {
			t.Fatalf("entry sin FullPath: %+v", e)
		}
		if !fsforensic.HasForensicExtension(e.FileName) && !fsforensic.IsSuspiciousName(e.FileName) {
			t.Fatalf("entry no pasó el filtro forense: %q", e.FileName)
		}
	}
}

func TestErrUnsupportedIsDefined(t *testing.T) {
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("ErrUnsupported mal definido")
	}
}
