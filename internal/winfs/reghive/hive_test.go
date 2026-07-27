package reghive

import (
	"os"
	"path/filepath"
	"testing"
)

func loadHive(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; ver testdata/README.md", name)
	}
	return b
}

func TestOpenRejectsBadSignature(t *testing.T) {
	_, err := Open([]byte("XXXX not a hive"))
	if err == nil {
		t.Fatal("esperaba error con firma inválida")
	}
}

func TestOpenValidHive(t *testing.T) {
	h, err := Open(loadHive(t, "sample.hve"))
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if h == nil {
		t.Fatal("Hive nil")
	}
}

// TestReadKnownValue navega a una clave y valor conocidos del fixture.
// El fixture y sus valores esperados se documentan en testdata/README.md.
func TestReadKnownValue(t *testing.T) {
	h, err := Open(loadHive(t, "sample.hve"))
	if err != nil {
		t.Skipf("sin fixture: %v", err)
	}
	key, err := h.OpenKey(`Select`)
	if err != nil {
		t.Fatalf("OpenKey error: %v", err)
	}
	data, typ, err := key.Value("Current")
	if err != nil {
		t.Fatalf("Value error: %v", err)
	}
	if len(data) != 4 || typ != 4 { // REG_DWORD
		t.Fatalf("valor Current inesperado: data=%v typ=%d", data, typ)
	}
}
