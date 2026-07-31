package report

import "time"

// MachineInfo describe el estado de la máquina examinada.
type MachineInfo struct {
	OS            string   `json:"os"`
	Build         string   `json:"build"`
	UptimeMinutes int      `json:"uptimeMinutes"`
	Elevated      bool     `json:"elevated"`
	VM            bool     `json:"vm"`
	VMReasons     []string `json:"vmReasons,omitempty"`
}

// Finding es un hallazgo forense individual.
type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"` // ANTI_FORENSIC | EXECUTION | PERSISTENCE | EMULATOR | KNOWN_CHEAT
	Severity   string     `json:"severity"` // INFO | LOW | MEDIUM | HIGH | CRITICAL
	Confidence float64    `json:"confidence"`
	Title      string     `json:"title"`
	Evidence   string     `json:"evidence"`
	Artifact   string     `json:"artifact"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

// Niveles posibles del veredicto global.
const (
	LevelLimpio          = "LIMPIO"
	LevelSospechoso      = "SOSPECHOSO"
	LevelEvidenciaFuerte = "EVIDENCIA_FUERTE"
	// LevelIncompleto se usa cuando no se halló evidencia PERO algún colector
	// falló: el agente no puede afirmar "limpio" sobre lo que no llegó a ver.
	LevelIncompleto = "INCOMPLETO"
)

// Verdict es la conclusión global del escaneo.
type Verdict struct {
	Level            string   `json:"level"`
	Summary          string   `json:"summary"`
	Reasons          []string `json:"reasons,omitempty"`
	FailedCollectors []string `json:"failedCollectors,omitempty"`
}

// Report es el reporte firmado con cadena de custodia.
type Report struct {
	SessionID    string      `json:"sessionId"`
	Platform     string      `json:"platform"` // "windows"
	AgentVersion string      `json:"agentVersion"`
	StartedAt    time.Time   `json:"startedAt"`
	EndedAt      time.Time   `json:"endedAt"`
	ConsentAt    time.Time   `json:"consentAt"`
	Machine      MachineInfo `json:"machine"`
	Findings     []Finding   `json:"findings"`
	Verdict      Verdict     `json:"verdict"`
	HashChain    []string    `json:"hashChain"`
	Signature    string      `json:"signature"`
	Status       string      `json:"status"` // COMPLETE | ABORTED | ERROR
}
