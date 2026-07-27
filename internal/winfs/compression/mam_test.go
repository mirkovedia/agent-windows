//go:build windows

package compression

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; generar según testdata/README.md", name)
	}
	return b
}

func TestDecompressMAMPassthroughWithoutSignature(t *testing.T) {
	raw := []byte("no es un archivo MAM")
	out, err := DecompressMAM(raw)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("sin firma MAM debería devolver los datos intactos")
	}
}

func TestDecompressMAMRejectsTruncatedHeader(t *testing.T) {
	_, err := DecompressMAM([]byte("MAM\x04\x01")) // header incompleto
	if err == nil {
		t.Fatal("esperaba error con header MAM truncado")
	}
}

// TestDecompressMAMRoundTrip valida contra un blob comprimido real.
// El fixture se genera en Windows con RtlCompressBuffer (ver testdata/README).
func TestDecompressMAMRoundTrip(t *testing.T) {
	compressed := loadFixture(t, "sample_mam.bin")    // blob MAM\x04 real
	expected := loadFixture(t, "sample_mam.expected") // contenido esperado
	out, err := DecompressMAM(compressed)
	if err != nil {
		t.Fatalf("DecompressMAM error: %v", err)
	}
	if !bytes.Equal(out, expected) {
		t.Fatalf("descompresión incorrecta: got %d bytes, want %d", len(out), len(expected))
	}
}
