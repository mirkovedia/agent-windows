// internal/verdict/verdict.go
package verdict

import (
	"fmt"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
)

// Evaluate convierte los resultados crudos de los colectores en hallazgos
// clasificados más un veredicto global. Es una función total: nunca devuelve
// error ni entra en panic ante datos corruptos.
func Evaluate(results []collector.Result) ([]report.Finding, report.Verdict) {
	var items []evaluated
	var failed []string
	var summaries []report.Finding

	for _, res := range results {
		if res.Err != nil {
			failed = append(failed, res.Collector)
			items = append(items, evaluated{
				finding: report.Finding{
					ID:         "collector-error-" + res.Collector,
					Category:   CatAntiForensic,
					Severity:   SevInfo,
					Confidence: 0.1,
					Title:      "Colector " + res.Collector + " falló",
					Evidence:   res.Err.Error(),
					Artifact:   res.Collector,
				},
				artType: "collector_error",
			})
			continue
		}

		neutralTotal, neutralEmitted := 0, 0
		for i, a := range res.Artifacts {
			rule := escalate(a, ruleFor(a.Type))
			neutral := isNeutral(a.Type)
			if neutral {
				neutralTotal++
				// La evidencia neutra que no escaló se cuenta pero no se
				// emite: es el ruido normal de una computadora en uso.
				if rule.Severity == SevInfo {
					continue
				}
				neutralEmitted++
			}
			at, hasTime := timeOf(a)
			items = append(items, evaluated{
				finding: report.Finding{
					ID:         fmt.Sprintf("%s-%d", res.Collector, i),
					Category:   rule.Category,
					Severity:   rule.Severity,
					Confidence: rule.Confidence,
					Title:      titleFor(a.Type),
					Evidence:   string(a.Data),
					Artifact:   a.Source,
				},
				artType: a.Type,
				at:      at,
				hasTime: hasTime,
			})
		}
		if neutralTotal > 0 {
			summaries = append(summaries, summaryFinding(res.Collector, neutralTotal, neutralEmitted))
		}
	}

	items = applyCombos(items)

	findings := make([]report.Finding, 0, len(items)+len(summaries))
	for _, it := range items {
		findings = append(findings, it.finding)
	}
	findings = append(findings, summaries...)

	return findings, globalVerdict(findings, failed)
}

// titleFor da un título legible por tipo de artefacto.
func titleFor(artifactType string) string {
	switch artifactType {
	case "eventlog.log_cleared":
		return "Se borró un registro de eventos"
	case "mft_timestomp":
		return "Timestamps manipulados (timestomping)"
	case "eventlog.tamper_signal":
		return "Archivo de log alterado a nivel binario"
	case "eventlog.desync":
		return "Los eventos no coinciden con el estado del sistema"
	case "scheduled_task_desync":
		return "Tarea programada desincronizada con el registro"
	case "service_driver":
		return "Driver instalado fuera de la ruta estándar"
	case "scheduled_task":
		return "Tarea programada oculta o sospechosa"
	case "deleted_entry":
		return "Archivo borrado recuperado del MFT"
	}
	return "Artefacto " + artifactType
}

// globalVerdict deriva la conclusión del escaneo a partir de los hallazgos.
func globalVerdict(findings []report.Finding, failed []string) report.Verdict {
	var criticals, highs, mediums int
	highCategories := make(map[string]bool)
	var reasons []string

	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			criticals++
			highCategories[f.Category] = true
			reasons = append(reasons, f.Title)
		case SevHigh:
			highs++
			highCategories[f.Category] = true
			reasons = append(reasons, f.Title)
		case SevMedium:
			mediums++
		}
	}

	level := report.LevelLimpio
	switch {
	case criticals > 0, highs >= 2 && len(highCategories) >= 2:
		level = report.LevelEvidenciaFuerte
	case highs > 0, mediums >= 2:
		level = report.LevelSospechoso
	}

	// Un escaneo degradado no puede afirmarse limpio: el agente no vio todo.
	// Los niveles con evidencia NO se degradan; el fallo queda listado aparte.
	if level == report.LevelLimpio && len(failed) > 0 {
		level = report.LevelIncompleto
	}

	return report.Verdict{
		Level:            level,
		Summary:          summaryFor(level, criticals, highs, mediums, failed),
		Reasons:          reasons,
		FailedCollectors: failed,
	}
}

// summaryFor arma una línea en lenguaje llano para el veredicto.
func summaryFor(level string, criticals, highs, mediums int, failed []string) string {
	switch level {
	case report.LevelEvidenciaFuerte:
		return fmt.Sprintf("Evidencia fuerte: %d señales críticas y %d de alta severidad.", criticals, highs)
	case report.LevelSospechoso:
		return fmt.Sprintf("Indicios a revisar: %d señales de alta severidad y %d de severidad media.", highs, mediums)
	case report.LevelIncompleto:
		return fmt.Sprintf("Sin hallazgos, pero el escaneo fue parcial: fallaron %d colectores.", len(failed))
	}
	return "Sin hallazgos relevantes."
}
