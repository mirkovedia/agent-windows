//go:build windows

// internal/collector/prefetch/prefetch.go
package prefetch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
)

// Collector recolecta y parsea los archivos Prefetch del sistema.
type Collector struct {
	Dir string
}

// New crea el colector con el directorio Prefetch por defecto.
func New() *Collector {
	return &Collector{Dir: `C:\Windows\Prefetch`}
}

func (c *Collector) Name() string  { return "prefetch" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	pattern := filepath.Join(c.Dir, "*.pf")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var artifacts []collector.Artifact
	for _, f := range files {
		select {
		case <-ctx.Done():
			return artifacts, ctx.Err()
		default:
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue // archivo inaccesible: se omite, no se aborta
		}
		entry, err := parsePrefetch(raw)
		if err != nil {
			continue
		}
		data, _ := json.Marshal(entry)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "prefetch",
			Source:    f,
			Data:      data,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
