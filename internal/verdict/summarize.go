// internal/verdict/summarize.go
package verdict

import (
	"fmt"

	"github.com/telagem/agent-windows/internal/report"
)

// summaryFinding colapsa la evidencia neutra de un colector en un solo
// hallazgo INFO. total es cuántos artefactos neutros produjo el colector;
// emitted, cuántos de ellos se emitieron además como hallazgo propio por
// haber escalado. La diferencia queda representada por el conteo: el reporte
// nunca oculta cuánta evidencia se decidió no destacar.
func summaryFinding(collectorName string, total, emitted int) report.Finding {
	return report.Finding{
		ID:         "summary-" + collectorName,
		Category:   CatExecution,
		Severity:   SevInfo,
		Confidence: 0.0,
		Title:      "Evidencia de ejecución: " + collectorName,
		Evidence: fmt.Sprintf(
			"%d artefactos registrados, %d emitidos individualmente por coincidir con patrones sospechosos",
			total, emitted),
		Artifact: collectorName,
	}
}
