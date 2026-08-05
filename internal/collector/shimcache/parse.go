// internal/collector/shimcache/parse.go
package shimcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/wintext"
	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Entry es un ejecutable visto por el sistema según ShimCache.
type Entry struct {
	Path         string    `json:"path"`
	ModifiedTime time.Time `json:"modifiedTime"`
}

var win10Magic = []byte("10ts")

// Offsets de header conocidos del AppCompatCache. El primer DWORD del blob es
// el offset donde arrancan las entradas, y cada versión de Windows usa el
// suyo: 0x30 en Win10 RTM–1511, 0x34 desde 1607 en adelante (incluido Win11).
const (
	headerWin10RTM   = 0x30
	headerWin10_1607 = 0x34
)

// parseAppCompatCache parsea el blob binario del valor AppCompatCache.
// Implementa el formato Win10/Win11 (entradas "10ts").
func parseAppCompatCache(blob []byte) ([]Entry, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob AppCompatCache vacío o truncado")
	}
	// El primer DWORD es el offset a la primera entrada, no una firma opaca.
	// Se lo usa como offset en vez de asumir un tamaño fijo: con la constante
	// hardcodeada, un blob de Win10 1607+ (0x34) empezaba a leerse 4 bytes
	// antes, el magic "10ts" no matcheaba y no se parseaba ni una entrada.
	headerSize := int(binary.LittleEndian.Uint32(blob[0:4]))
	if headerSize != headerWin10RTM && headerSize != headerWin10_1607 {
		return nil, fmt.Errorf(
			"offset de header AppCompatCache no soportado: 0x%x (blob de %d bytes, primeros bytes: % x)",
			headerSize, len(blob), blob[:min(16, len(blob))])
	}
	if len(blob) < headerSize {
		return nil, fmt.Errorf("blob más corto que el header: %d bytes", len(blob))
	}
	var entries []Entry
	pos := headerSize
	for pos+12 <= len(blob) {
		if !bytes.Equal(blob[pos:pos+4], win10Magic) {
			break
		}
		// magic(4) + unknown(4) + dataSize(4)
		dataSize := int(binary.LittleEndian.Uint32(blob[pos+8 : pos+12]))
		recStart := pos + 12
		if recStart+dataSize > len(blob) {
			break
		}
		rec := blob[recStart : recStart+dataSize]
		e, err := parseWin10Record(rec)
		if err == nil {
			entries = append(entries, e)
		}
		pos = recStart + dataSize
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no se parsearon entradas ShimCache")
	}
	return entries, nil
}

// parseWin10Record parsea un registro "10ts": pathLen(2) + path + FILETIME(8).
func parseWin10Record(rec []byte) (Entry, error) {
	if len(rec) < 2 {
		return Entry{}, fmt.Errorf("registro truncado")
	}
	pathLen := int(binary.LittleEndian.Uint16(rec[0:2]))
	if 2+pathLen+8 > len(rec) {
		return Entry{}, fmt.Errorf("registro truncado (path)")
	}
	path := wintext.DecodeUTF16(rec[2 : 2+pathLen])
	ft := binary.LittleEndian.Uint64(rec[2+pathLen : 2+pathLen+8])
	return Entry{Path: path, ModifiedTime: wintime.FiletimeToTime(ft)}, nil
}
