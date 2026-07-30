// Package eventlog correlaciona Event Logs (.evtx) contra el estado actual
// del registro para detectar desincronizaciones (evidencia de borrado de
// logs o inyección manual).
package eventlog

import (
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// InstallEvent es un evento 7045 (instalación de servicio) parseado del EVTX.
type InstallEvent struct {
	ServiceName string
	ImagePath   string
}

// TaskEvent es un evento 106/140/141 de TaskScheduler/Operational.
type TaskEvent struct {
	Action   string // "register", "update", "delete"
	TaskName string
}

// Desync es una discrepancia entre logs y estado actual.
type Desync struct {
	Kind    string
	Subject string
	Note    string
}

const clearedNote = "esperable por borrado de logs"

// CrossCheck aplica las reglas de desincronización. currentServices y
// currentTasks ya vienen filtrados por el colector a la superficie no
// estándar (drivers no-Microsoft, tareas fuera de Microsoft\) para no
// generar ruido con miles de artefactos legítimos del sistema.
func CrossCheck(
	installs []InstallEvent,
	currentServices []winservices.DriverService,
	taskEvents []TaskEvent,
	currentTasks []winscheduler.CachedTask,
	logsCleared bool,
) []Desync {
	var out []Desync

	for _, s := range currentServices {
		if !hasInstall(installs, s.Name) {
			out = append(out, Desync{Kind: "service_no_install_log", Subject: s.Name})
		}
	}
	for _, in := range installs {
		if !hasService(currentServices, in.ServiceName) {
			out = append(out, Desync{Kind: "service_installed_then_removed", Subject: in.ServiceName})
		}
	}
	for _, t := range currentTasks {
		if !hasTaskEvent(taskEvents, "register", t.RelPath) {
			out = append(out, Desync{Kind: "task_no_register_log", Subject: t.RelPath})
		}
	}
	for _, e := range taskEvents {
		if e.Action == "delete" && hasTask(currentTasks, e.TaskName) {
			out = append(out, Desync{Kind: "task_delete_desync", Subject: e.TaskName})
		}
	}

	if logsCleared {
		for i := range out {
			out[i].Note = clearedNote
		}
	}
	return out
}

func hasInstall(installs []InstallEvent, name string) bool {
	for _, in := range installs {
		if in.ServiceName == name {
			return true
		}
	}
	return false
}

func hasService(services []winservices.DriverService, name string) bool {
	for _, s := range services {
		if s.Name == name {
			return true
		}
	}
	return false
}

func hasTaskEvent(events []TaskEvent, action, relPath string) bool {
	for _, e := range events {
		if e.Action == action && taskMatches(relPath, e.TaskName) {
			return true
		}
	}
	return false
}

func hasTask(tasks []winscheduler.CachedTask, name string) bool {
	for _, t := range tasks {
		if taskMatches(t.RelPath, name) {
			return true
		}
	}
	return false
}

// taskMatches compara por elemento final de la ruta: los eventos suelen dar
// "\Updater" mientras el registro da "Updater" o "Foo\Updater".
func taskMatches(relPath, name string) bool {
	return lastElem(relPath) == lastElem(name)
}

func lastElem(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
