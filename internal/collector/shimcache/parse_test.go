package shimcache

import (
	"encoding/binary"
	"testing"
)

func TestParseAppCompatCacheWin10Signature(t *testing.T) {
	// Header Win10: offset 0x30 al primer registro; magic "10ts" en cada entrada.
	blob := make([]byte, 0x30)
	binary.LittleEndian.PutUint32(blob[0:4], 0x34) // offset de header Win10

	entry := buildWin10Entry("C:\\Windows\\System32\\evil.exe", 0x01D9B1DED53E8000)
	blob = append(blob, entry...)

	entries, err := parseAppCompatCache(blob)
	if err != nil {
		t.Fatalf("parseAppCompatCache error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Path != "C:\\Windows\\System32\\evil.exe" {
		t.Fatalf("path = %q", entries[0].Path)
	}
}

func TestParseAppCompatCacheRejectsEmpty(t *testing.T) {
	if _, err := parseAppCompatCache(nil); err == nil {
		t.Fatal("esperaba error con blob vacío")
	}
}

// buildWin10Entry construye una entrada "10ts" para el test.
func buildWin10Entry(path string, filetime uint64) []byte {
	pathUTF16 := make([]byte, 0, len(path)*2)
	for _, r := range path {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(r))
		pathUTF16 = append(pathUTF16, b[:]...)
	}
	e := []byte("10ts")
	e = append(e, 0, 0, 0, 0) // unknown
	dataSize := 12 + 2 + len(pathUTF16)
	sz := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz, uint32(dataSize))
	e = append(e, sz...)
	pl := make([]byte, 2)
	binary.LittleEndian.PutUint16(pl, uint16(len(pathUTF16)))
	e = append(e, pl...)
	e = append(e, pathUTF16...)
	ft := make([]byte, 8)
	binary.LittleEndian.PutUint64(ft, filetime)
	e = append(e, ft...)
	dsz := make([]byte, 4)
	e = append(e, dsz...) // data size = 0
	return e
}
