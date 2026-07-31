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

// escalateByName sube dos niveles si el Source matchea un marcador de
// fsforensic, con un tope que depende del peso de la evidencia:
//
//   - marcador fuerte (cheat, aimbot, ...): tope HIGH. CRITICAL se reserva a
//     los combos, porque un nombre feo por sí solo no es la afirmación más
//     grave que el motor puede hacer.
//   - marcador débil (token exacto: hook, esp, loader, ...): tope MEDIUM. Un
//     "run-hook.cmd" borrado es un script de desarrollo, no evidencia forense.
func escalateByName(a collector.Artifact, r Rule) Rule {
	strong := fsforensic.HasStrongMarker(a.Source)
	if !strong && !fsforensic.IsSuspiciousName(a.Source) {
		return r
	}
	cap := SevMedium
	if strong {
		cap = SevHigh
	}
	raised := bumpSeverity(r.Severity, 2)
	if severityRank(raised) > severityRank(cap) {
		raised = cap
	}
	// Nunca bajar: si la regla base ya era más grave, se respeta.
	if severityRank(raised) < severityRank(r.Severity) {
		raised = r.Severity
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
	case "eventlog.tamper_signal":
		return tamperSignalRule(a, r)
	}
	return r
}

// nonEvidenceTamperKinds son señales que NO prueban manipulación:
//   - log_unreadable: el log no se pudo abrir. TaskScheduler/Operational viene
//     deshabilitado por defecto en Windows, así que "no existe" es lo normal.
//   - dirty_flag / full_flag: banderas esperables en un snapshot VSS de un log
//     que estaba abierto y escribiéndose.
//
// Reportar "no pude verificar" como evidencia es justamente el error que hay
// que evitar en una herramienta que puede sancionar a alguien.
var nonEvidenceTamperKinds = map[string]bool{
	"log_unreadable": true,
	"dirty_flag":     true,
	"full_flag":      true,
}

// tamperSignalRule baja a INFO las señales que no distinguen manipulación de
// condiciones normales. chunk_crc_invalid, record_id_gap y truncated se
// mantienen en HIGH: esos sí implican edición binaria del archivo.
func tamperSignalRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Kind string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if nonEvidenceTamperKinds[payload.Kind] {
		r.Severity = SevInfo
		r.Confidence = 0.0
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
