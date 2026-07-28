package prefetch

import (
	"os"
	"path/filepath"
	"testing"
)

func loadPF(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; ver testdata/README.md", name)
	}
	return b
}

func TestParsePrefetchRejectsGarbage(t *testing.T) {
	if _, err := parsePrefetch([]byte("no soy un pf")); err == nil {
		t.Fatal("esperaba error con datos inválidos")
	}
}

// TestParsePrefetchWin10 valida contra un .pf real de Win10 (v30, comprimido).
func TestParsePrefetchWin10(t *testing.T) {
	e, err := parsePrefetch(loadPF(t, "NOTEPAD.EXE-v30.pf"))
	if err != nil {
		t.Fatalf("parsePrefetch error: %v", err)
	}
	if e.ExecutableName == "" {
		t.Fatal("ExecutableName vacío")
	}
	if e.Version != 30 {
		t.Fatalf("Version = %d, want 30", e.Version)
	}
	if e.RunCount == 0 {
		t.Fatal("RunCount = 0, se esperaba > 0 en el fixture")
	}
}
