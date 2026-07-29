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
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "deleted_entries" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	entries, err := ntfs.ScanDeleted(ctx, c.Volume)
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
