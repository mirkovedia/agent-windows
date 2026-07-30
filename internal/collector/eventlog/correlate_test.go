package eventlog

import (
	"testing"

	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

func hasDesync(ds []Desync, kind, subject string) bool {
	for _, d := range ds {
		if d.Kind == kind && d.Subject == subject {
			return true
		}
	}
	return false
}

func TestServiceWithoutInstallLog(t *testing.T) {
	current := []winservices.DriverService{{Name: "EvilDrv", ImagePath: `C:\Temp\evil.sys`}}
	ds := CrossCheck(nil, current, nil, nil, false)
	if !hasDesync(ds, "service_no_install_log", "EvilDrv") {
		t.Fatalf("esperaba service_no_install_log para EvilDrv, obtuve %+v", ds)
	}
}

func TestServiceInstalledThenRemoved(t *testing.T) {
	installs := []InstallEvent{{ServiceName: "EvilDrv", ImagePath: `C:\Temp\evil.sys`}}
	ds := CrossCheck(installs, nil, nil, nil, false)
	if !hasDesync(ds, "service_installed_then_removed", "EvilDrv") {
		t.Fatalf("esperaba service_installed_then_removed, obtuve %+v", ds)
	}
}

func TestTaskDeleteDesync(t *testing.T) {
	events := []TaskEvent{{Action: "delete", TaskName: "Updater"}}
	current := []winscheduler.CachedTask{{RelPath: "Updater", ID: "{GUID}"}}
	ds := CrossCheck(nil, nil, events, current, false)
	if !hasDesync(ds, "task_delete_desync", "Updater") {
		t.Fatalf("esperaba task_delete_desync, obtuve %+v", ds)
	}
}

func TestLogsClearedAnnotation(t *testing.T) {
	current := []winservices.DriverService{{Name: "EvilDrv"}}
	ds := CrossCheck(nil, current, nil, nil, true)
	if len(ds) == 0 || ds[0].Note == "" {
		t.Fatalf("con logsCleared debería anotarse Note, obtuve %+v", ds)
	}
}
