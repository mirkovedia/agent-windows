// internal/collector/services/services.go
package services

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// Collector recolecta drivers no estándar del subárbol Services del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "services" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		root, err = h.OpenKey(`ControlSet002\Services`)
		if err != nil {
			return nil, err
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0)
	for _, s := range all {
		select {
		case <-ctx.Done():
			return artifacts, ctx.Err()
		default:
		}
		if !winservices.IsNonMicrosoftDriver(s) {
			continue
		}
		b, _ := json.Marshal(s)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "service_driver",
			Source:    s.ImagePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
