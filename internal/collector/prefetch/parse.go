//go:build windows

// internal/collector/prefetch/parse.go
package prefetch

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/compression"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Entry es un archivo Prefetch parseado.
type Entry struct {
	ExecutableName string
	PathHash       string
	RunCount       uint32
	LastRunTimes   []time.Time
	Volumes        []string
	LoadedFiles    []string
	Version        uint32
}

// parsePrefetch descomprime (si es MAM) y parsea un .pf según su versión.
func parsePrefetch(raw []byte) (Entry, error) {
	data, err := compression.DecompressMAM(raw)
	if err != nil {
		return Entry{}, fmt.Errorf("descompresión MAM: %w", err)
	}
	if len(data) < 84 || string(data[4:8]) != "SCCA" {
		return Entry{}, fmt.Errorf("firma SCCA ausente")
	}
	version := binary.LittleEndian.Uint32(data[0:4])

	// Nombre del ejecutable: UTF-16LE en offset 0x10, hasta 60 bytes.
	name := wintext.DecodeUTF16(data[0x10:0x4C])

	e := Entry{
		ExecutableName: name,
		Version:        version,
	}

	// Offsets de metadatos según versión.
	var runCountOffset, lastRunOffset int
	switch version {
	case 23: // Win7
		lastRunOffset = 0x80
		runCountOffset = 0x98
	case 26: // Win8.1
		lastRunOffset = 0x80
		runCountOffset = 0xD0
	case 30, 31: // Win10 / Win11
		lastRunOffset = 0x80
		runCountOffset = 0xD0
	default:
		return Entry{}, fmt.Errorf("versión de prefetch no soportada: %d", version)
	}

	if runCountOffset+4 <= len(data) {
		e.RunCount = binary.LittleEndian.Uint32(data[runCountOffset : runCountOffset+4])
	}
	// Hasta 8 timestamps FILETIME de 8 bytes.
	for i := 0; i < 8; i++ {
		off := lastRunOffset + i*8
		if off+8 > len(data) {
			break
		}
		ft := binary.LittleEndian.Uint64(data[off : off+8])
		if ft == 0 {
			continue
		}
		e.LastRunTimes = append(e.LastRunTimes, wintime.FiletimeToTime(ft))
	}
	return e, nil
}

