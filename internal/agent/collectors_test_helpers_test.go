package agent

import (
	"context"

	"github.com/telagem/agent-windows/internal/collector"
)

type memCollector struct{}

func (memCollector) Name() string  { return "mem" }
func (memCollector) Priority() int { return collector.PriorityVolatile }
func (memCollector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	return []collector.Artifact{{Type: "mem", Source: "test", Data: []byte(`{"x":1}`)}}, nil
}

func testCollectors() []collector.Collector { return []collector.Collector{memCollector{}} }
