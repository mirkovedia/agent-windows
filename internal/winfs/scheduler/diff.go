// internal/winfs/scheduler/diff.go
package scheduler

// DesyncKind distingue las dos direcciones de desincronización.
type DesyncKind string

const (
	// HiveOnly: TaskCache referencia una tarea sin XML en disco. Señal
	// fuerte — alguien borró el archivo visible pero no pudo (o no supo)
	// limpiar el registro.
	HiveOnly DesyncKind = "hive_only"
	// FileOnly: el XML existe pero no está en TaskCache. Señal débil/
	// ambigua (puede ser una condición de carrera de creación reciente).
	FileOnly DesyncKind = "file_only"
)

// Desync es una discrepancia entre las tareas en disco y las registradas en TaskCache.
type Desync struct {
	RelPath     string
	Kind        DesyncKind
	TaskCacheID string // solo poblado si Kind == HiveOnly
}

// DiffTasks compara el set COMPLETO de tareas en disco (sin filtrar por
// sospecha) contra el de TaskCache y devuelve las discrepancias. Debe
// recibir el listado completo: una tarea borrada del disco por definición no
// puede pasar un filtro de "sospechoso" (ya no existe para evaluarla), así
// que filtrar antes de diffear perdería justamente la detección hive_only.
func DiffTasks(onDisk []TaskDefinition, cached []CachedTask) []Desync {
	diskSet := make(map[string]bool, len(onDisk))
	for _, t := range onDisk {
		diskSet[t.RelPath] = true
	}
	cacheSet := make(map[string]bool, len(cached))
	for _, c := range cached {
		cacheSet[c.RelPath] = true
	}

	var out []Desync
	for _, c := range cached {
		if !diskSet[c.RelPath] {
			out = append(out, Desync{RelPath: c.RelPath, Kind: HiveOnly, TaskCacheID: c.ID})
		}
	}
	for _, t := range onDisk {
		if !cacheSet[t.RelPath] {
			out = append(out, Desync{RelPath: t.RelPath, Kind: FileOnly})
		}
	}
	return out
}
