//go:build windows

// internal/agent/live_windows.go
package agent

import (
	"context"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/collector/amcache"
	"github.com/telagem/agent-windows/internal/collector/bam"
	"github.com/telagem/agent-windows/internal/collector/prefetch"
	"github.com/telagem/agent-windows/internal/collector/shimcache"
	usncol "github.com/telagem/agent-windows/internal/collector/usn"
	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
	"github.com/telagem/agent-windows/internal/winfs/vss"
)

// RunLive arma los colectores reales (tomando hives desde un snapshot VSS) y
// ejecuta el flujo completo con consentimiento ya otorgado por el CLI.
func RunLive(ctx context.Context, opts Options, up transport.Uploader) (report.Report, error) {
	systemHive := `C:\Windows\System32\config\SYSTEM`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
	}

	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}
