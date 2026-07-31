// internal/verdict/escalate.go
package verdict

import (
	"encoding/json"
	"strings"

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
// de un campo de su payload.
func escalateByDetail(a collector.Artifact, r Rule) Rule {
	switch a.Type {
	case "scheduled_task_desync":
		return desyncTaskRule(a, r)
	case "eventlog.desync":
		return eventDesyncRule(a, r)
	case "scheduled_task":
		return scheduledTaskRule(a, r)
	case "service_driver":
		return serviceDriverRule(a, r)
	}
	return r
}

// desyncTaskRule pondera la dirección de la desincronía XML-registro: cambia
// radicalmente lo que significa.
func desyncTaskRule(a collector.Artifact, r Rule) Rule {
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

// eventDesyncRule baja a INFO la única dirección que no puede ser sana.
func eventDesyncRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Kind string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if payload.Kind == "task_no_register_log" {
		// Los Event Logs rotan: una tarea registrada hace meses nunca va a
		// tener su evento 106 disponible. La ausencia no prueba nada, así que
		// se reporta para auditoría pero no mueve el veredicto.
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// scheduledTaskRule baja a INFO las tareas propias de Windows: el sistema trae
// decenas marcadas como ocultas y no son señal por sí solas.
func scheduledTaskRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		RelPath string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if strings.HasPrefix(strings.ToLower(payload.RelPath), `microsoft\`) {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// normalDriverLocations son ubicaciones donde el software instalado deja sus
// drivers de forma legítima (antivirus, GPU, VPN, virtualización).
var normalDriverLocations = []string{
	`\program files\`,
	`\program files (x86)\`,
	`\windows\system32\driverstore\`,
}

// serviceDriverRule baja a INFO los drivers en ubicaciones normales de
// instalación. La heurística de Fase 3C es por ruta, no por firma, así que sin
// este ajuste marca decenas de drivers legítimos en cualquier máquina real.
func serviceDriverRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		ImagePath string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	lower := strings.ToLower(payload.ImagePath)
	for _, loc := range normalDriverLocations {
		if strings.Contains(lower, loc) {
			r.Severity = SevInfo
			r.Confidence = 0.0
			return r
		}
	}
	return r
}
