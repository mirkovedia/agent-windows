//go:build windows

// internal/collector/usn/usn.go
package usn

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	winusn "github.com/telagem/agent-windows/internal/winfs/usn"
)

// Collector lee eventos relevantes del USN Change Journal del volumen.
type Collector struct {
	Volume string
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "usn" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	entries, err := winusn.ReadJournal(ctx, c.Volume)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "usn",
			Source:    e.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
