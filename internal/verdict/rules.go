// internal/verdict/rules.go

// Package verdict convierte artefactos forenses crudos en hallazgos con
// severidad y un veredicto global. Es puro: no hace I/O, no depende de
// Windows y se testea con collector.Result sintéticos.
package verdict

// Severidades, en orden creciente de gravedad.
const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

// Categorías de hallazgo (subconjunto de las declaradas en report.Finding que
// esta fase realmente produce).
const (
	CatAntiForensic = "ANTI_FORENSIC"
	CatExecution    = "EXECUTION"
	CatPersistence  = "PERSISTENCE"
)

// Rule es la clasificación base de un tipo de artefacto, antes de escalar.
type Rule struct {
	Category   string
	Severity   string
	Confidence float64
}

// severityOrder define el orden total de severidades.
var severityOrder = []string{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}

// baseRules asigna una regla a cada tipo de artefacto conocido. Los tipos
// ausentes se tratan como evidencia neutra (ver ruleFor).
var baseRules = map[string]Rule{
	// Señales fuertes: baja frecuencia, alto valor forense.
	"eventlog.log_cleared":   {CatAntiForensic, SevHigh, 0.9},
	"mft_timestomp":          {CatAntiForensic, SevHigh, 0.8},
	"eventlog.tamper_signal": {CatAntiForensic, SevHigh, 0.7},
	"eventlog.desync":        {CatAntiForensic, SevMedium, 0.6},
	// scheduled_task_desync arranca en el medio y lo define su Kind (escalate.go):
	// hive_only sube a HIGH, file_only baja a LOW. Si el Data no parsea, queda acá.
	"scheduled_task_desync": {CatAntiForensic, SevMedium, 0.5},
	"service_driver":        {CatPersistence, SevMedium, 0.5},
	"scheduled_task":        {CatPersistence, SevMedium, 0.5},
	"deleted_entry":         {CatAntiForensic, SevLow, 0.3},
}

// neutralRule es la clasificación de la evidencia de ejecución normal y de
// cualquier tipo que el motor no conozca.
var neutralRule = Rule{Category: CatExecution, Severity: SevInfo, Confidence: 0.0}

// ruleFor devuelve la regla base de un tipo. Un tipo desconocido (colector
// nuevo sin regla) cae en neutro: el motor nunca falla por no conocerlo.
func ruleFor(artifactType string) Rule {
	if r, ok := baseRules[artifactType]; ok {
		return r
	}
	return neutralRule
}

// isNeutral reporta si el tipo es evidencia de alto volumen que debe
// colapsarse en un resumen en vez de emitirse artefacto por artefacto.
func isNeutral(artifactType string) bool {
	_, known := baseRules[artifactType]
	return !known
}

// severityRank traduce una severidad a su posición en el orden total.
// Una severidad desconocida se trata como INFO.
func severityRank(s string) int {
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return 0
}

// bumpSeverity sube una severidad la cantidad de niveles indicada, saturando
// en CRITICAL. levels negativo la baja.
func bumpSeverity(s string, levels int) string {
	r := severityRank(s) + levels
	if r < 0 {
		r = 0
	}
	if r >= len(severityOrder) {
		r = len(severityOrder) - 1
	}
	return severityOrder[r]
}
