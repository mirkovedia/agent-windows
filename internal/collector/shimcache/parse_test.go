package shimcache

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestParseAppCompatCacheHeaderSizes cubre las dos versiones del header. El
// primer DWORD es el offset donde arrancan las entradas, así que el blob debe
// construirse con esa misma cantidad de bytes de cabecera: 0x30 en Win10
// RTM–1511 y 0x34 desde 1607 en adelante, que es lo que corre en Win11.
func TestParseAppCompatCacheHeaderSizes(t *testing.T) {
	for _, headerSize := range []int{0x30, 0x34} {
		blob := make([]byte, headerSize)
		binary.LittleEndian.PutUint32(blob[0:4], uint32(headerSize))
		blob = append(blob, buildWin10Entry(`C:\Windows\System32\evil.exe`, 0x01D9B1DED53E8000)...)

		entries, err := parseAppCompatCache(blob)
		if err != nil {
			t.Errorf("header 0x%x: %v", headerSize, err)
			continue
		}
		if len(entries) != 1 {
			t.Errorf("header 0x%x: len(entries) = %d, want 1", headerSize, len(entries))
			continue
		}
		if entries[0].Path != `C:\Windows\System32\evil.exe` {
			t.Errorf("header 0x%x: path = %q", headerSize, entries[0].Path)
		}
	}
}

// TestParseAppCompatCacheRejectsUnknownHeader deja constancia de que un header
// desconocido se rechaza con contexto suficiente para diagnosticarlo, en vez
// de devolver entradas basura.
func TestParseAppCompatCacheRejectsUnknownHeader(t *testing.T) {
	blob := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(blob[0:4], 0x126264) // la celda "db" cruda
	_, err := parseAppCompatCache(blob)
	if err == nil {
		t.Fatal("esperaba error con un header desconocido")
	}
	if !strings.Contains(err.Error(), "0x126264") {
		t.Fatalf("el error debe incluir el valor leído: %v", err)
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
