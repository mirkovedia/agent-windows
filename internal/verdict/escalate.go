// internal/verdict/escalate.go
package verdict

import (
	"encoding/json"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
)

// suspiciousConfidence es la confianza que se fija cuando el nombre del
// artefacto matchea un marcador conocido.
const suspiciousConfidence = 0.8

// escalate ajusta la regla base según el contenido del artefacto: primero por
// detalle específico del tipo, después por nombre sospechoso.
func escalate(a collector.Artifact, base Rule) Rule {
	r := escalateByDetail(a, base)
	return escalateByName(a, r)
}

// escalateByName sube dos niveles (con tope en HIGH) si el Source matchea un
// marcador de fsforensic. El tope existe porque CRITICAL se reserva a los
// combos: un nombre feo es señal fuerte, pero no la afirmación más grave.
func escalateByName(a collector.Artifact, r Rule) Rule {
	if !fsforensic.IsSuspiciousName(a.Source) {
		return r
	}
	raised := bumpSeverity(r.Severity, 2)
	if severityRank(raised) > severityRank(SevHigh) {
		raised = SevHigh
	}
	r.Severity = raised
	r.Confidence = suspiciousConfidence
	return r
}

// escalateByDetail aplica el ajuste específico de los tipos cuyo peso depende
// de un campo de su payload. Hoy solo scheduled_task_desync lo necesita: la
// dirección de la desincronía cambia radicalmente lo que significa.
func escalateByDetail(a collector.Artifact, r Rule) Rule {
	if a.Type != "scheduled_task_desync" {
		return r
	}
	var payload struct {
		Kind string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r // payload ilegible: se queda con la regla base
	}
	switch payload.Kind {
	case "hive_only":
		// El XML fue borrado pero la entrada sigue en TaskCache: alguien
		// borró el archivo visible y no pudo limpiar el registro.
		r.Severity = SevHigh
		r.Confidence = 0.8
	case "file_only":
		// El XML existe sin entrada en el registro: puede ser una tarea
		// recién creada (condición de carrera legítima).
		r.Severity = SevLow
		r.Confidence = 0.3
	}
	return r
}
