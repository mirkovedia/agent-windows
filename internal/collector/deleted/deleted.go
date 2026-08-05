//go:build windows

// internal/collector/deleted/deleted.go
package deleted

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/ntfs"
)

// Collector recupera metadatos de archivos borrados del volumen vía lectura raw del MFT.
type Collector struct {
	Volume string
	// progress lo inyecta el runner cuando hay una interfaz escuchando.
	progress func(done, total int64)
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "deleted_entries" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

// SetProgress implementa collector.Reporter: recorrer la MFT entera tarda
// decenas de segundos y sin avance la barra queda congelada todo ese rato.
func (c *Collector) SetProgress(fn func(done, total int64)) { c.progress = fn }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	entries, err := ntfs.ScanDeleted(ctx, c.Volume, c.progress)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "deleted_entry",
			Source:    e.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
