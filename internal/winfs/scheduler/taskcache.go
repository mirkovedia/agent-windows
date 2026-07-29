// internal/winfs/scheduler/taskcache.go
package scheduler

import (
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// CachedTask es una entrada hoja del árbol TaskCache\Tree con su Id (GUID).
type CachedTask struct {
	RelPath string // misma convención de ruta relativa que TaskDefinition
	ID      string // valor "Id" (GUID) de la subclave hoja
}

// WalkTaskCacheTree recorre recursivamente la clave Tree y devuelve toda
// hoja que tenga un valor "Id" (las claves intermedias sin ese valor son
// carpetas, no tareas).
func WalkTaskCacheTree(treeKey *reghive.Key) ([]CachedTask, error) {
	return walkTree(treeKey, ""), nil
}

func walkTree(key *reghive.Key, prefix string) []CachedTask {
	var out []CachedTask
	if raw, _, err := key.Value("Id"); err == nil {
		out = append(out, CachedTask{RelPath: prefix, ID: wintext.DecodeUTF16(raw)})
	}
	subs, err := key.Subkeys()
	if err != nil {
		return out // celda malformada: se corta ahí, no aborta el resto del árbol
	}
	for _, s := range subs {
		childPath := s.Name()
		if prefix != "" {
			childPath = prefix + `\` + s.Name()
		}
		out = append(out, walkTree(s, childPath)...)
	}
	return out
}
