// internal/collector/shimcache/shimcache.go
package shimcache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

// Collector lee el AppCompatCache del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "shimcache" }
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
	blob, err := readAppCompatCacheValue(h)
	if err != nil {
		return nil, err
	}
	entries, err := parseAppCompatCache(blob)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "shimcache",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

func readAppCompatCacheValue(h *reghive.Hive) ([]byte, error) {
	for _, cs := range []string{"ControlSet001", "ControlSet002"} {
		key, err := h.OpenKey(cs + `\Control\Session Manager\AppCompatCache`)
		if err != nil {
			continue
		}
		blob, _, err := key.Value("AppCompatCache")
		if err == nil {
			return blob, nil
		}
	}
	return nil, fmt.Errorf("valor AppCompatCache no encontrado")
}
