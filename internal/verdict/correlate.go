// internal/verdict/correlate.go
package verdict

import (
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
)

// timeOf extrae el instante en que ocurrió el hecho que describe el artefacto,
// no cuándo se recolectó (Artifact.Collected no sirve para correlacionar).
//
// Solo algunos tipos exponen una fecha utilizable; el resto devuelve false y
// queda fuera del amplificador temporal. Las structs de winfs serializan con
// el nombre del campo Go (SI, Timestamp) porque no llevan tags json; las de
// collector/eventlog sí llevan tags en minúscula (time).
func timeOf(a collector.Artifact) (time.Time, bool) {
	switch a.Type {
	case "mft_timestomp", "deleted_entry":
		var p struct {
			SI struct {
				Created time.Time
			}
		}
		if err := json.Unmarshal(a.Data, &p); err != nil || p.SI.Created.IsZero() {
			return time.Time{}, false
		}
		return p.SI.Created, true

	case "usn":
		var p struct {
			Timestamp time.Time
		}
		if err := json.Unmarshal(a.Data, &p); err != nil || p.Timestamp.IsZero() {
			return time.Time{}, false
		}
		return p.Timestamp, true

	case "eventlog.session_timeline", "eventlog.log_cleared":
		var p struct {
			Time time.Time `json:"time"`
		}
		if err := json.Unmarshal(a.Data, &p); err != nil || p.Time.IsZero() {
			return time.Time{}, false
		}
		return p.Time, true
	}
	return time.Time{}, false
}

// correlationWindow es la ventana dentro de la cual dos señales con timestamp
// se consideran parte del mismo episodio.
const correlationWindow = 30 * time.Minute

// temporalBoost es cuánta confianza suma el amplificador temporal.
const temporalBoost = 0.1

// evaluated es un hallazgo junto al contexto que los combos necesitan y que
// report.Finding no guarda: de qué tipo de artefacto salió y cuándo ocurrió.
type evaluated struct {
	finding report.Finding
	artType string
	at      time.Time
	hasTime bool
}

// applyCombos aplica las reglas de co-ocurrencia sobre el conjunto de
// hallazgos de un mismo escaneo. Son deliberadamente pocas: cada combo es una
// afirmación fuerte y su falso positivo es caro.
func applyCombos(items []evaluated) []evaluated {
	applyAntiForensicCluster(items)
	applyPersistenceWithClearedLogs(items)
	return items
}

// applyAntiForensicCluster: dos o más señales ANTI_FORENSIC de tipos DISTINTOS
// con severidad >= MEDIUM elevan a CRITICAL la más grave del grupo. Borrar
// logs y timestompear y editar el .evtx es un patrón deliberado; una sola de
// esas cosas puede tener explicación inocente.
func applyAntiForensicCluster(items []evaluated) {
	var idx []int
	types := make(map[string]bool)
	for i, it := range items {
		if it.finding.Category == CatAntiForensic && severityRank(it.finding.Severity) >= severityRank(SevMedium) {
			idx = append(idx, i)
			types[it.artType] = true
		}
	}
	if len(types) < 2 {
		return
	}
	top := highestOf(items, idx)
	if top < 0 {
		return
	}
	items[top].finding.Severity = SevCritical
	amplify(items, top, idx)
}

// applyPersistenceWithClearedLogs: un mecanismo de persistencia presente junto
// a un borrado de logs eleva la persistencia a CRITICAL. Hay algo instalado y
// el registro de cuándo se instaló desapareció.
func applyPersistenceWithClearedLogs(items []evaluated) {
	var cleared []int
	var persistence []int
	for i, it := range items {
		switch {
		case it.artType == "eventlog.log_cleared":
			cleared = append(cleared, i)
		case it.artType == "service_driver" || it.artType == "scheduled_task":
			persistence = append(persistence, i)
		}
	}
	if len(cleared) == 0 || len(persistence) == 0 {
		return
	}
	top := highestOf(items, persistence)
	if top < 0 {
		return
	}
	items[top].finding.Severity = SevCritical
	amplify(items, top, cleared)
}

// highestOf devuelve el índice del hallazgo más grave entre los indicados.
// Desempata por el primero. Devuelve -1 si la lista está vacía.
func highestOf(items []evaluated, idx []int) int {
	best := -1
	for _, i := range idx {
		if best == -1 || severityRank(items[i].finding.Severity) > severityRank(items[best].finding.Severity) {
			best = i
		}
	}
	return best
}

// amplify suma temporalBoost a la confianza de items[target] si alguno de los
// hallazgos relacionados ocurrió dentro de la ventana de correlación. Solo
// aplica cuando ambos lados exponen tiempo: nunca inventa una fecha.
func amplify(items []evaluated, target int, related []int) {
	if !items[target].hasTime {
		return
	}
	for _, i := range related {
		if i == target || !items[i].hasTime {
			continue
		}
		delta := items[target].at.Sub(items[i].at)
		if delta < 0 {
			delta = -delta
		}
		if delta <= correlationWindow {
			c := items[target].finding.Confidence + temporalBoost
			if c > 1.0 {
				c = 1.0
			}
			items[target].finding.Confidence = c
			return
		}
	}
}
