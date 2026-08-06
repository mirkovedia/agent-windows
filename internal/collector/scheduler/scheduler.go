// internal/collector/scheduler/scheduler.go
package scheduler

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	disk, walkErr := c.readTasksDir(ctx)
	if walkErr != nil && len(disk.tasks) == 0 {
		return nil, walkErr // no se pudo enumerar nada: falla dura
	}

	artifacts := make([]collector.Artifact, 0)

	// Si el hive SOFTWARE no está disponible, se omite el cross-check pero se
	// sigue con las tareas en disco: perder toda la señal de tareas por un
	// fallo transitorio de VSS en una sola de las dos fuentes es peor que
	// degradar con gracia.
	if cached, err := c.readTaskCache(); err == nil {
		for _, d := range winscheduler.DiffTasks(disk.tasks, cached) {
			// Una tarea que el registro conoce pero que vive en un directorio
			// que no pudimos listar NO es una tarea borrada: es una tarea que
			// no llegamos a mirar. Afirmar lo contrario es inventar evidencia.
			if d.Kind == winscheduler.HiveOnly && isUnderAny(d.RelPath, disk.unreadableDirs) {
				continue
			}
			b, _ := json.Marshal(d)
			artifacts = append(artifacts, collector.Artifact{
				Type:      "scheduled_task_desync",
				Source:    d.RelPath,
				Data:      b,
				Collected: time.Now(),
			})
		}
	}

	// Dejar constancia de los huecos de enumeración: sin esto, un escaneo
	// parcial se ve idéntico a uno completo.
	if len(disk.unreadableDirs) > 0 {
		b, _ := json.Marshal(map[string]any{
			"Dirs":   len(disk.unreadableDirs),
			"Sample": firstN(disk.unreadableDirs, 5),
		})
		artifacts = append(artifacts, collector.Artifact{
			Type:      "scheduled_task_scan_incomplete",
			Source:    c.TasksDir,
			Data:      b,
			Collected: time.Now(),
		})
	}

	for _, t := range disk.tasks {
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

// diskScan es el resultado de enumerar el directorio de tareas: las tareas
// encontradas y los subdirectorios que no se pudieron listar.
type diskScan struct {
	tasks []winscheduler.TaskDefinition
	// unreadableDirs son rutas relativas cuyo contenido nunca se enumeró.
	// De esas tareas no sabemos NADA: no se puede afirmar que fueron borradas.
	unreadableDirs []string
}

// readTasksDir enumera recursivamente TasksDir y parsea cada archivo como
// definición de tarea. Un archivo individual corrupto o inaccesible se registra
// igual como presente; un directorio que no se puede listar se anota aparte.
// Solo un fallo en la raíz misma es un error real.
func (c *Collector) readTasksDir(ctx context.Context) (diskScan, error) {
	var scan diskScan
	err := filepath.WalkDir(c.TasksDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == c.TasksDir {
				return err
			}
			// Windows protege con ACL varios de sus propios directorios de
			// tareas. Sus hijos nunca se visitan, así que hay que recordar el
			// hueco: sin esto el cross-check los reporta como borrados.
			if rel, relErr := filepath.Rel(c.TasksDir, path); relErr == nil {
				scan.unreadableDirs = append(scan.unreadableDirs, rel)
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
		rel, err := filepath.Rel(c.TasksDir, path)
		if err != nil {
			return nil
		}
		// WalkDir ya probó que el archivo EXISTE. Si después no se puede leer
		// o parsear (Windows pone ACLs restrictivas en varias de sus propias
		// tareas), igual se registra como presente en disco: descartarla haría
		// que el cross-check contra TaskCache la reporte como borrada, que es
		// afirmar algo que no sabemos. Queda sin Command/Hidden, así que el
		// filtro de tareas reportables no la va a destacar.
		raw, err := os.ReadFile(path)
		if err != nil {
			scan.tasks = append(scan.tasks, winscheduler.TaskDefinition{RelPath: rel})
			return nil
		}
		t, err := winscheduler.ParseTaskXML(raw, rel)
		if err != nil {
			scan.tasks = append(scan.tasks, winscheduler.TaskDefinition{RelPath: rel})
			return nil
		}
		scan.tasks = append(scan.tasks, t)
		return nil
	})
	return scan, err
}

// firstN devuelve hasta n elementos, para muestras de diagnóstico.
func firstN(items []string, n int) []string {
	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

// isUnderAny reporta si relPath cae dentro de alguno de los directorios dados.
func isUnderAny(relPath string, dirs []string) bool {
	lower := strings.ToLower(relPath)
	for _, d := range dirs {
		ld := strings.ToLower(d)
		if lower == ld || strings.HasPrefix(lower, ld+`\`) {
			return true
		}
	}
	return false
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
