//go:build windows

// internal/agent/live_windows.go
package agent

import (
	"context"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/collector/amcache"
	"github.com/telagem/agent-windows/internal/collector/bam"
	deletedcol "github.com/telagem/agent-windows/internal/collector/deleted"
	eventlogcol "github.com/telagem/agent-windows/internal/collector/eventlog"
	mftcol "github.com/telagem/agent-windows/internal/collector/mft"
	"github.com/telagem/agent-windows/internal/collector/prefetch"
	schedulercol "github.com/telagem/agent-windows/internal/collector/scheduler"
	servicescol "github.com/telagem/agent-windows/internal/collector/services"
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
	softwareHive := `C:\Windows\System32\config\SOFTWARE`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`
	securityLog := `C:\Windows\System32\winevt\Logs\Security.evtx`
	systemLog := `C:\Windows\System32\winevt\Logs\System.evtx`
	taskSchedLog := `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		softwareHive = vss.PathIn(snap, `Windows\System32\config\SOFTWARE`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
		securityLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Security.evtx`)
		systemLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\System.evtx`)
		taskSchedLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`)
	}

	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		deletedcol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
		servicescol.New(systemHive),
		schedulercol.New(`C:\Windows\System32\Tasks`, softwareHive),
		eventlogcol.New(securityLog, systemLog, taskSchedLog, systemHive, softwareHive),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}
