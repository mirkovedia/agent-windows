// internal/collector/scheduler/scheduler.go
package scheduler

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
)

// Collector recolecta tareas programadas sospechosas/ocultas y su cross-check
// contra TaskCache.
type Collector struct {
	TasksDir         string
	SoftwareHivePath string
}

// New crea el colector con la carpeta Tasks y el hive SOFTWARE dados.
func New(tasksDir, softwareHivePath string) *Collector {
	return &Collector{TasksDir: tasksDir, SoftwareHivePath: softwareHivePath}
}

func (c *Collector) Name() string  { return "scheduled_tasks" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	onDisk, walkErr := c.readTasksDir(ctx)
	if walkErr != nil && len(onDisk) == 0 {
		return nil, walkErr // no se pudo enumerar nada: falla dura
	}

	artifacts := make([]collector.Artifact, 0)

	// Si el hive SOFTWARE no está disponible, se omite el cross-check pero se
	// sigue con las tareas en disco: perder toda la señal de tareas por un
	// fallo transitorio de VSS en una sola de las dos fuentes es peor que
	// degradar con gracia.
	if cached, err := c.readTaskCache(); err == nil {
		for _, d := range winscheduler.DiffTasks(onDisk, cached) {
			b, _ := json.Marshal(d)
			artifacts = append(artifacts, collector.Artifact{
				Type:      "scheduled_task_desync",
				Source:    d.RelPath,
				Data:      b,
				Collected: time.Now(),
			})
		}
	}

	for _, t := range onDisk {
		if !isReportable(t) {
			continue
		}
		b, _ := json.Marshal(t)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "scheduled_task",
			Source:    t.RelPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, walkErr
}

// isReportable filtra a tareas ocultas o con comando/argumentos de nombre
// sospechoso. No se usa fsforensic.HasForensicExtension aquí: a diferencia
// de USN (donde se combina con la razón del evento), el Command de una tarea
// programada casi siempre apunta a un .exe, así que esa extensión no
// discrimina nada — reportaría prácticamente cualquier tarea del sistema.
func isReportable(t winscheduler.TaskDefinition) bool {
	if t.Hidden {
		return true
	}
	return fsforensic.IsSuspiciousName(t.Command) || fsforensic.IsSuspiciousName(t.Arguments)
}

// readTasksDir enumera recursivamente TasksDir y parsea cada archivo como
// definición de tarea. Un archivo individual corrupto o inaccesible se
// omite; solo un fallo en la raíz misma es un error real.
func (c *Collector) readTasksDir(ctx context.Context) ([]winscheduler.TaskDefinition, error) {
	var out []winscheduler.TaskDefinition
	err := filepath.WalkDir(c.TasksDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == c.TasksDir {
				return err
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(c.TasksDir, path)
		if err != nil {
			return nil
		}
		t, err := winscheduler.ParseTaskXML(raw, rel)
		if err != nil {
			return nil // XML corrupto o no-XML: se omite
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

// readTaskCache abre el hive SOFTWARE y camina TaskCache\Tree.
func (c *Collector) readTaskCache() ([]winscheduler.CachedTask, error) {
	data, err := os.ReadFile(c.SoftwareHivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	treeKey, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`)
	if err != nil {
		return nil, err
	}
	return winscheduler.WalkTaskCacheTree(treeKey)
}
