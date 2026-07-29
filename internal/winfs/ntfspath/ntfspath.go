package ntfspath

import "strings"

// ParentEntry es una fila del mapa de rutas construido con ENUM_USN_DATA.
type ParentEntry struct {
	Name      string
	ParentRef uint64
}

const (
	// unresolvedPrefix marca un tramo de ruta cuyo directorio padre ya no existe
	// (p.ej. un archivo borrado cuyo padre también fue borrado).
	unresolvedPrefix = "<sin-resolver>"

	// rootRecordNumber es el nº de entrada MFT de la raíz del volumen NTFS.
	rootRecordNumber = 5

	// maxDepth acota la subida para evitar ciclos en mapas corruptos.
	maxDepth = 256
)

// isRoot compara solo los 48 bits bajos (nº de entrada MFT) para ignorar la
// secuencia, que puede variar entre snapshots.
func isRoot(ref uint64) bool {
	return ref&0x0000FFFFFFFFFFFF == rootRecordNumber
}

// ResolvePath reconstruye la ruta absoluta subiendo por parentMap desde
// parentRef. Corta en la raíz; si un padre falta, antepone unresolvedPrefix.
func ResolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string {
	parts := []string{leaf}
	ref := parentRef
	for depth := 0; depth < maxDepth; depth++ {
		if isRoot(ref) {
			break
		}
		entry, ok := parentMap[ref]
		if !ok {
			parts = append(parts, unresolvedPrefix)
			break
		}
		parts = append(parts, entry.Name)
		ref = entry.ParentRef
	}
	// parts está de hoja a raíz; invertir para raíz→hoja.
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return `\` + strings.Join(parts, `\`)
}
