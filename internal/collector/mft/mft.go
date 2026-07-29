//go:build windows

package mft

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
)

// Collector detecta timestomping en archivos forenses del volumen vía MFT.
type Collector struct {
	Volume string
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "mft_timestomp" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	findings, err := winmft.ScanTimestomp(ctx, c.Volume)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(findings))
	for _, f := range findings {
		b, _ := json.Marshal(f)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "mft_timestomp",
			Source:    f.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
