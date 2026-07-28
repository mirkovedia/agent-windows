// internal/collector/shimcache/parse.go
package shimcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Entry es un ejecutable visto por el sistema según ShimCache.
type Entry struct {
	Path         string    `json:"path"`
	ModifiedTime time.Time `json:"modifiedTime"`
}

var win10Magic = []byte("10ts")

// win10HeaderSize es el tamaño fijo del header AppCompatCache en Win10/11.
// Las entradas "10ts" empiezan siempre en este offset.
const win10HeaderSize = 0x30

// parseAppCompatCache parsea el blob binario del valor AppCompatCache.
// Implementa el formato Win10/Win11 (entradas "10ts").
func parseAppCompatCache(blob []byte) ([]Entry, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob AppCompatCache vacío o truncado")
	}
	// Los primeros 4 bytes son la firma de versión: 0x30 (Win10 RTM) o
	// 0x34 (Win10 1607+). No es un offset: las entradas siguen a un header
	// de tamaño fijo 0x30.
	signature := binary.LittleEndian.Uint32(blob[0:4])
	if signature != 0x30 && signature != 0x34 {
		return nil, fmt.Errorf("firma AppCompatCache no soportada: 0x%x", signature)
	}
	if len(blob) < win10HeaderSize {
		return nil, fmt.Errorf("blob más corto que el header: %d bytes", len(blob))
	}
	var entries []Entry
	pos := win10HeaderSize
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
	path := decodeUTF16(rec[2 : 2+pathLen])
	ft := binary.LittleEndian.Uint64(rec[2+pathLen : 2+pathLen+8])
	return Entry{Path: path, ModifiedTime: filetimeToTime(ft)}, nil
}

func decodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}
