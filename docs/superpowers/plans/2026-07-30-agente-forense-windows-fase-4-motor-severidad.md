# Fase 4 — Motor de Severidad y Veredicto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convertir los artefactos crudos de los 11 colectores en hallazgos con categoría, severidad y confianza, colapsar la evidencia neutra, combinar señales que juntas significan más, y emitir un veredicto global que nunca afirme "limpio" sobre un escaneo degradado.

**Architecture:** Un paquete puro nuevo `internal/verdict` con una única entrada pública `Evaluate(results []collector.Result) ([]report.Finding, report.Verdict)`, que reemplaza a `resultToFindings` en `runWithCollectors`. El resto del flujo (cadena de hash, firma, upload) queda intacto porque opera sobre los findings resultantes. Al ser una función pura sin I/O, todo el set de reglas se testea con `collector.Result` sintéticos.

**Tech Stack:** Go 1.25+, solo stdlib (`encoding/json`, `fmt`, `sort`, `strings`, `time`). Paquetes internos: `collector`, `report`, `winfs/fsforensic`.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, sin CGO (`CGO_ENABLED=0`).
- Go 1.25+ (go.mod declara `go 1.25.0`). Module path: `github.com/telagem/agent-windows`.
- Sin dependencias externas nuevas. Esta fase no necesita `golang.org/x/sys`.
- **Ningún archivo de esta fase lleva build tag** `//go:build windows`: el motor es puro y debe correr y testearse en cualquier host.
- Un colector que falla nunca tumba el escaneo.
- `Evaluate` es una función total: nunca devuelve error ni entra en panic ante datos corruptos.
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Escala de severidad (referencia para todo el plan)

```
INFO(0) < LOW(1) < MEDIUM(2) < HIGH(3) < CRITICAL(4)
```

- Escalado por contenido: `min(rank+2, HIGH)`. `LOW→HIGH`, `INFO→MEDIUM`, `MEDIUM→HIGH`.
- `CRITICAL` lo producen **solo** los combos (Task 6).

## Estructura de archivos

```
internal/report/report.go        (modificar) tipo Verdict + campo Report.Verdict  — Task 1
internal/verdict/rules.go        tabla de regla base por tipo + orden de severidad — Task 2
internal/verdict/escalate.go     escalado por contenido y por detalle             — Task 3
internal/verdict/summarize.go    colapso de evidencia neutra                      — Task 4
internal/verdict/correlate.go    combos de co-ocurrencia + extracción de tiempo   — Task 5, 6
internal/verdict/verdict.go      Evaluate + veredicto global                      — Task 6
internal/agent/agent.go          (modificar) usar Evaluate, borrar resultToFindings — Task 7
```

---

### Task 1: Tipo `Verdict` en el paquete `report`

**Files:**
- Modify: `internal/report/report.go`
- Test: `internal/report/verdict_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type Verdict struct { Level, Summary string; Reasons, FailedCollectors []string }`
  - Constantes `LevelLimpio = "LIMPIO"`, `LevelSospechoso = "SOSPECHOSO"`, `LevelEvidenciaFuerte = "EVIDENCIA_FUERTE"`, `LevelIncompleto = "INCOMPLETO"`
  - `Report` gana el campo `Verdict Verdict \`json:"verdict"\``

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/report/verdict_test.go
package report

import (
	"encoding/json"
	"testing"
)

func TestVerdictLevelsAreDistinct(t *testing.T) {
	levels := map[string]bool{
		LevelLimpio:          true,
		LevelSospechoso:      true,
		LevelEvidenciaFuerte: true,
		LevelIncompleto:      true,
	}
	if len(levels) != 4 {
		t.Fatalf("los cuatro niveles deben ser distintos, obtuve %d", len(levels))
	}
}

func TestReportCarriesVerdictInJSON(t *testing.T) {
	r := Report{
		SessionID: "s1",
		Verdict: Verdict{
			Level:            LevelIncompleto,
			Summary:          "escaneo degradado",
			Reasons:          []string{"colector mft falló"},
			FailedCollectors: []string{"mft_timestomp"},
		},
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Verdict.Level != LevelIncompleto {
		t.Fatalf("Level = %q, want %q", got.Verdict.Level, LevelIncompleto)
	}
	if len(got.Verdict.FailedCollectors) != 1 || got.Verdict.FailedCollectors[0] != "mft_timestomp" {
		t.Fatalf("FailedCollectors = %+v", got.Verdict.FailedCollectors)
	}
	if got.Verdict.Summary != "escaneo degradado" {
		t.Fatalf("Summary = %q", got.Verdict.Summary)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/report/ -run 'TestVerdict|TestReportCarries'`
Expected: FAIL de compilación — `undefined: LevelLimpio`, `undefined: Verdict`.

- [ ] **Step 3: Implementar el tipo**

En `internal/report/report.go`, agregar antes de `// Report es el reporte firmado...`:

```go
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
```

Y agregar el campo a `Report`, después de `Findings`:

```go
	Findings     []Finding   `json:"findings"`
	Verdict      Verdict     `json:"verdict"`
```

- [ ] **Step 4: Correr el test — debe pasar**

Run: `go test ./internal/report/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report/report.go internal/report/verdict_test.go
git commit -m "feat: tipo Verdict y campo Report.Verdict

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Reglas base por tipo de artefacto (`rules.go`)

**Files:**
- Create: `internal/verdict/rules.go`
- Test: `internal/verdict/rules_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type Rule struct { Category, Severity string; Confidence float64 }`
  - `func ruleFor(artifactType string) Rule`
  - `func isNeutral(artifactType string) bool`
  - `func severityRank(s string) int`
  - `func bumpSeverity(s string, levels int) string` (satura en `CRITICAL`)
  - Constantes de severidad `SevInfo`, `SevLow`, `SevMedium`, `SevHigh`, `SevCritical`
  - Constantes de categoría `CatAntiForensic`, `CatExecution`, `CatPersistence`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/verdict/rules_test.go
package verdict

import "testing"

func TestRuleForStrongSignals(t *testing.T) {
	cases := []struct {
		artifactType string
		category     string
		severity     string
	}{
		{"eventlog.log_cleared", CatAntiForensic, SevHigh},
		{"mft_timestomp", CatAntiForensic, SevHigh},
		{"eventlog.tamper_signal", CatAntiForensic, SevHigh},
		{"eventlog.desync", CatAntiForensic, SevMedium},
		{"scheduled_task_desync", CatAntiForensic, SevMedium},
		{"service_driver", CatPersistence, SevMedium},
		{"scheduled_task", CatPersistence, SevMedium},
		{"deleted_entry", CatAntiForensic, SevLow},
	}
	for _, c := range cases {
		r := ruleFor(c.artifactType)
		if r.Category != c.category || r.Severity != c.severity {
			t.Errorf("%s: got %s/%s, want %s/%s", c.artifactType, r.Category, r.Severity, c.category, c.severity)
		}
		if r.Confidence <= 0 {
			t.Errorf("%s: una señal fuerte debe tener confianza > 0", c.artifactType)
		}
	}
}

func TestNeutralTypesAreInfo(t *testing.T) {
	for _, tp := range []string{"prefetch", "bam", "shimcache", "amcache", "usn", "eventlog.session_timeline"} {
		r := ruleFor(tp)
		if r.Severity != SevInfo || r.Category != CatExecution {
			t.Errorf("%s: got %s/%s, want %s/%s", tp, r.Category, r.Severity, CatExecution, SevInfo)
		}
		if !isNeutral(tp) {
			t.Errorf("%s debería ser neutro", tp)
		}
	}
}

func TestUnknownTypeIsNeutral(t *testing.T) {
	r := ruleFor("colector_del_futuro")
	if r.Severity != SevInfo || r.Category != CatExecution {
		t.Fatalf("tipo desconocido debe caer en neutro, got %s/%s", r.Category, r.Severity)
	}
	if !isNeutral("colector_del_futuro") {
		t.Fatal("tipo desconocido debe contarse como neutro")
	}
}

func TestStrongTypesAreNotNeutral(t *testing.T) {
	if isNeutral("mft_timestomp") {
		t.Fatal("mft_timestomp no es evidencia neutra")
	}
}

func TestSeverityRankOrder(t *testing.T) {
	if !(severityRank(SevInfo) < severityRank(SevLow) &&
		severityRank(SevLow) < severityRank(SevMedium) &&
		severityRank(SevMedium) < severityRank(SevHigh) &&
		severityRank(SevHigh) < severityRank(SevCritical)) {
		t.Fatal("el orden de severidad es incorrecto")
	}
}

func TestBumpSeveritySaturates(t *testing.T) {
	if got := bumpSeverity(SevLow, 2); got != SevHigh {
		t.Errorf("LOW+2 = %s, want HIGH", got)
	}
	if got := bumpSeverity(SevInfo, 2); got != SevMedium {
		t.Errorf("INFO+2 = %s, want MEDIUM", got)
	}
	if got := bumpSeverity(SevHigh, 2); got != SevCritical {
		t.Errorf("HIGH+2 debe saturar en CRITICAL, got %s", got)
	}
	if got := bumpSeverity(SevCritical, 1); got != SevCritical {
		t.Errorf("CRITICAL no puede subir más, got %s", got)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/verdict/`
Expected: FAIL de compilación — `undefined: ruleFor`, `undefined: CatAntiForensic`, etc.

- [ ] **Step 3: Implementar `rules.go`**

```go
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
```

- [ ] **Step 4: Correr el test — debe pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/verdict/rules.go internal/verdict/rules_test.go
git commit -m "feat: tabla de reglas base por tipo de artefacto y orden de severidad

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Escalado por contenido y por detalle (`escalate.go`)

**Files:**
- Create: `internal/verdict/escalate.go`
- Test: `internal/verdict/escalate_test.go`

**Interfaces:**
- Consumes: `Rule`, `bumpSeverity`, `severityRank`, `SevHigh`, `SevLow` (Task 2); `collector.Artifact`; `fsforensic.IsSuspiciousName(name string) bool`.
- Produces: `func escalate(a collector.Artifact, base Rule) Rule`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/verdict/escalate_test.go
package verdict

import (
	"encoding/json"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func art(artifactType, source string, data any) collector.Artifact {
	b, _ := json.Marshal(data)
	return collector.Artifact{Type: artifactType, Source: source, Data: b}
}

func TestEscalateSuspiciousNameRaisesTwoLevels(t *testing.T) {
	// deleted_entry base es LOW; con nombre sospechoso debe llegar a HIGH.
	a := art("deleted_entry", `C:\Temp\aimbot_loader.exe`, nil)
	got := escalate(a, ruleFor("deleted_entry"))
	if got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH", got.Severity)
	}
	if got.Confidence != 0.8 {
		t.Fatalf("Confidence = %v, want 0.8", got.Confidence)
	}
}

func TestEscalateNeutralSuspiciousBecomesMedium(t *testing.T) {
	// prefetch base es INFO; con nombre sospechoso debe llegar a MEDIUM.
	a := art("prefetch", `C:\Windows\Prefetch\INJECTOR.EXE-1234.pf`, nil)
	got := escalate(a, ruleFor("prefetch"))
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
}

func TestEscalateCapsAtHigh(t *testing.T) {
	// service_driver base es MEDIUM; +2 saturaría en CRITICAL, pero el
	// escalado por contenido tiene tope HIGH (CRITICAL es solo de combos).
	a := art("service_driver", `C:\Temp\cheatdrv.sys`, nil)
	got := escalate(a, ruleFor("service_driver"))
	if got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH (tope del escalado por contenido)", got.Severity)
	}
}

func TestEscalateCleanNameUnchanged(t *testing.T) {
	a := art("deleted_entry", `C:\Users\mirko\Documents\informe.docx`, nil)
	base := ruleFor("deleted_entry")
	got := escalate(a, base)
	if got.Severity != base.Severity || got.Confidence != base.Confidence {
		t.Fatalf("un nombre limpio no debe escalar: got %+v, base %+v", got, base)
	}
}

func TestEscalateDesyncHiveOnly(t *testing.T) {
	a := art("scheduled_task_desync", "Updater", map[string]string{"Kind": "hive_only"})
	got := escalate(a, ruleFor("scheduled_task_desync"))
	if got.Severity != SevHigh {
		t.Fatalf("hive_only debe ser HIGH, got %s", got.Severity)
	}
	if got.Confidence != 0.8 {
		t.Fatalf("Confidence = %v, want 0.8", got.Confidence)
	}
}

func TestEscalateDesyncFileOnly(t *testing.T) {
	a := art("scheduled_task_desync", "Updater", map[string]string{"Kind": "file_only"})
	got := escalate(a, ruleFor("scheduled_task_desync"))
	if got.Severity != SevLow {
		t.Fatalf("file_only debe ser LOW, got %s", got.Severity)
	}
}

func TestEscalateCorruptDataKeepsBase(t *testing.T) {
	a := collector.Artifact{Type: "scheduled_task_desync", Source: "X", Data: []byte("{no es json")}
	base := ruleFor("scheduled_task_desync")
	got := escalate(a, base)
	if got.Severity != base.Severity {
		t.Fatalf("Data corrupta debe dejar la regla base, got %s want %s", got.Severity, base.Severity)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/verdict/ -run TestEscalate`
Expected: FAIL de compilación — `undefined: escalate`.

- [ ] **Step 3: Implementar `escalate.go`**

```go
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
```

- [ ] **Step 4: Correr el test — debe pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/verdict/escalate.go internal/verdict/escalate_test.go
git commit -m "feat: escalado de severidad por nombre sospechoso y por detalle del artefacto

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Colapso de evidencia neutra (`summarize.go`)

**Files:**
- Create: `internal/verdict/summarize.go`
- Test: `internal/verdict/summarize_test.go`

**Interfaces:**
- Consumes: `CatExecution`, `SevInfo` (Task 2); `report.Finding`.
- Produces: `func summaryFinding(collectorName string, total, emitted int) report.Finding`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/verdict/summarize_test.go
package verdict

import (
	"strings"
	"testing"
)

func TestSummaryFindingCountsArtifacts(t *testing.T) {
	f := summaryFinding("prefetch", 1247, 3)
	if f.Severity != SevInfo || f.Category != CatExecution {
		t.Fatalf("el resumen debe ser INFO/EXECUTION, got %s/%s", f.Category, f.Severity)
	}
	if !strings.Contains(f.Evidence, "1247") {
		t.Fatalf("la evidencia debe informar el total, got %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "3") {
		t.Fatalf("la evidencia debe informar cuántos se emitieron aparte, got %q", f.Evidence)
	}
	if !strings.Contains(f.Title, "prefetch") {
		t.Fatalf("el título debe nombrar al colector, got %q", f.Title)
	}
	if f.ID == "" {
		t.Fatal("el resumen necesita ID para la cadena de hash")
	}
}

func TestSummaryFindingWithNoEscalations(t *testing.T) {
	f := summaryFinding("bam", 50, 0)
	if !strings.Contains(f.Evidence, "50") {
		t.Fatalf("Evidence = %q", f.Evidence)
	}
}

func TestSummaryFindingIDsAreDistinctPerCollector(t *testing.T) {
	a := summaryFinding("prefetch", 1, 0)
	b := summaryFinding("bam", 1, 0)
	if a.ID == b.ID {
		t.Fatal("dos colectores no pueden compartir el ID del resumen")
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/verdict/ -run TestSummary`
Expected: FAIL de compilación — `undefined: summaryFinding`.

- [ ] **Step 3: Implementar `summarize.go`**

```go
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
```

- [ ] **Step 4: Correr el test — debe pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/verdict/summarize.go internal/verdict/summarize_test.go
git commit -m "feat: colapso de evidencia neutra en hallazgos de resumen

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Extracción de tiempo por tipo (`correlate.go`, parte 1)

**Files:**
- Create: `internal/verdict/correlate.go`
- Test: `internal/verdict/correlate_test.go`

**Interfaces:**
- Consumes: `collector.Artifact`.
- Produces: `func timeOf(a collector.Artifact) (time.Time, bool)`

Nota sobre las formas JSON: las structs de `winfs` **no** llevan tags, así que
serializan con el nombre del campo Go (`SI`, `Timestamp`). Las de `collector/eventlog`
sí llevan tags en minúscula (`time`). Esto está verificado contra el código real.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/verdict/correlate_test.go
package verdict

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestTimeOfMFTTimestomp(t *testing.T) {
	want := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	a := art("mft_timestomp", `C:\x.exe`, map[string]any{
		"SI": map[string]any{"Created": want},
	})
	got, ok := timeOf(a)
	if !ok {
		t.Fatal("mft_timestomp debería exponer tiempo vía SI.Created")
	}
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTimeOfDeletedEntry(t *testing.T) {
	want := time.Date(2026, 7, 30, 11, 0, 0, 0, time.UTC)
	a := art("deleted_entry", `C:\y.exe`, map[string]any{
		"SI": map[string]any{"Created": want},
	})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfUSN(t *testing.T) {
	want := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	a := art("usn", `C:\z.exe`, map[string]any{"Timestamp": want})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfEventlogUsesLowercaseTag(t *testing.T) {
	want := time.Date(2026, 7, 30, 13, 0, 0, 0, time.UTC)
	a := art("eventlog.log_cleared", "Security", map[string]any{"time": want})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfTypesWithoutTime(t *testing.T) {
	for _, tp := range []string{"service_driver", "scheduled_task", "scheduled_task_desync", "eventlog.desync", "eventlog.tamper_signal"} {
		a := art(tp, "X", map[string]any{"Name": "algo"})
		if _, ok := timeOf(a); ok {
			t.Errorf("%s no debería exponer tiempo", tp)
		}
	}
}

func TestTimeOfCorruptDataIsNotFatal(t *testing.T) {
	a := collector.Artifact{Type: "usn", Source: "X", Data: []byte("{roto")}
	if _, ok := timeOf(a); ok {
		t.Fatal("un payload ilegible no puede reportar tiempo válido")
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/verdict/ -run TestTimeOf`
Expected: FAIL de compilación — `undefined: timeOf`.

- [ ] **Step 3: Implementar la extracción de tiempo**

```go
// internal/verdict/correlate.go
package verdict

import (
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
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
```

- [ ] **Step 4: Correr el test — debe pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/verdict/correlate.go internal/verdict/correlate_test.go
git commit -m "feat: extraccion de tiempo por tipo de artefacto para correlacion

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: Combos y veredicto global (`correlate.go` parte 2 + `verdict.go`)

**Files:**
- Modify: `internal/verdict/correlate.go` (agregar combos)
- Modify: `internal/verdict/correlate_test.go` (agregar tests de combos)
- Create: `internal/verdict/verdict.go`
- Test: `internal/verdict/verdict_test.go`

**Interfaces:**
- Consumes: todo lo anterior; `collector.Result`, `report.Finding`, `report.Verdict` y sus constantes de nivel.
- Produces:
  - `type evaluated struct { finding report.Finding; artType string; at time.Time; hasTime bool }`
  - `func applyCombos(items []evaluated) []evaluated`
  - `func Evaluate(results []collector.Result) ([]report.Finding, report.Verdict)`
  - `func globalVerdict(findings []report.Finding, failed []string) report.Verdict`

- [ ] **Step 1: Escribir los tests que fallan**

Agregar al final de `internal/verdict/correlate_test.go`:

```go
func ev(artType, category, severity string, conf float64, at time.Time, hasTime bool) evaluated {
	return evaluated{
		finding: report.Finding{
			ID: artType, Category: category, Severity: severity,
			Confidence: conf, Title: "t-" + artType,
		},
		artType: artType,
		at:      at,
		hasTime: hasTime,
	}
}

func maxSeverity(items []evaluated) string {
	best := SevInfo
	for _, it := range items {
		if severityRank(it.finding.Severity) > severityRank(best) {
			best = it.finding.Severity
		}
	}
	return best
}

func TestComboAntiForensicClusterRaisesToCritical(t *testing.T) {
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, time.Time{}, false),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if maxSeverity(got) != SevCritical {
		t.Fatalf("dos señales anti-forenses distintas deben producir CRITICAL, got %s", maxSeverity(got))
	}
}

func TestComboSameTypeRepeatedDoesNotCluster(t *testing.T) {
	items := []evaluated{
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if maxSeverity(got) == SevCritical {
		t.Fatal("el mismo tipo repetido no es un cluster: no debe escalar a CRITICAL")
	}
}

func TestComboPersistenceWithClearedLogs(t *testing.T) {
	items := []evaluated{
		ev("service_driver", CatPersistence, SevMedium, 0.5, time.Time{}, false),
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, time.Time{}, false),
	}
	got := applyCombos(items)
	var persistence evaluated
	for _, it := range got {
		if it.artType == "service_driver" {
			persistence = it
		}
	}
	if persistence.finding.Severity != SevCritical {
		t.Fatalf("persistencia + logs borrados debe ser CRITICAL, got %s", persistence.finding.Severity)
	}
}

func TestComboTemporalAmplifierWithinWindow(t *testing.T) {
	base := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, base, true),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, base.Add(10*time.Minute), true),
	}
	got := applyCombos(items)
	var maxConf float64
	for _, it := range got {
		if it.finding.Confidence > maxConf {
			maxConf = it.finding.Confidence
		}
	}
	if maxConf <= 0.9 {
		t.Fatalf("señales dentro de la ventana deben amplificar la confianza, got %v", maxConf)
	}
	if maxConf > 1.0 {
		t.Fatalf("la confianza no puede pasar de 1.0, got %v", maxConf)
	}
}

func TestComboNoAmplifierOutsideWindow(t *testing.T) {
	base := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, base, true),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, base.Add(5*time.Hour), true),
	}
	got := applyCombos(items)
	for _, it := range got {
		if it.finding.Confidence > 0.9 {
			t.Fatalf("fuera de la ventana no debe amplificarse, got %v", it.finding.Confidence)
		}
	}
}

func TestComboSingleSignalUnchanged(t *testing.T) {
	items := []evaluated{
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if got[0].finding.Severity != SevHigh {
		t.Fatalf("una sola señal no escala, got %s", got[0].finding.Severity)
	}
}
```

Y agregar el import de `report` al bloque de imports de ese archivo:
```go
	"github.com/telagem/agent-windows/internal/report"
```

`internal/verdict/verdict_test.go`:

```go
package verdict

import (
	"errors"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
)

func resultWith(name string, arts ...collector.Artifact) collector.Result {
	return collector.Result{Collector: name, Artifacts: arts}
}

func TestEvaluateCollapsesNeutralEvidence(t *testing.T) {
	var arts []collector.Artifact
	for i := 0; i < 100; i++ {
		arts = append(arts, art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil))
	}
	findings, _ := Evaluate([]collector.Result{resultWith("prefetch", arts...)})
	if len(findings) != 1 {
		t.Fatalf("100 artefactos neutros deben colapsar en 1 resumen, got %d", len(findings))
	}
	if findings[0].Severity != SevInfo {
		t.Fatalf("el resumen debe ser INFO, got %s", findings[0].Severity)
	}
}

func TestEvaluateEmitsSuspiciousNeutralIndividually(t *testing.T) {
	arts := []collector.Artifact{
		art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil),
		art("prefetch", `C:\Windows\Prefetch\INJECTOR.EXE-2.pf`, nil),
	}
	findings, _ := Evaluate([]collector.Result{resultWith("prefetch", arts...)})
	// 1 resumen + 1 individual escalado
	if len(findings) != 2 {
		t.Fatalf("esperaba resumen + 1 individual, got %d: %+v", len(findings), findings)
	}
	var sawMedium bool
	for _, f := range findings {
		if f.Severity == SevMedium {
			sawMedium = true
		}
	}
	if !sawMedium {
		t.Fatal("el prefetch sospechoso debe emitirse como MEDIUM")
	}
}

func TestEvaluateStrongSignalIsNotCollapsed(t *testing.T) {
	findings, _ := Evaluate([]collector.Result{
		resultWith("mft", art("mft_timestomp", `C:\x.exe`, nil)),
	})
	if len(findings) != 1 || findings[0].Severity != SevHigh {
		t.Fatalf("una señal fuerte se emite tal cual, got %+v", findings)
	}
}

func TestEvaluateFailedCollectorProducesFindingAndVerdict(t *testing.T) {
	res := collector.Result{Collector: "mft_timestomp", Err: errors.New("acceso denegado")}
	findings, v := Evaluate([]collector.Result{res})
	if len(findings) != 1 {
		t.Fatalf("un colector caído debe emitir un hallazgo, got %d", len(findings))
	}
	if len(v.FailedCollectors) != 1 || v.FailedCollectors[0] != "mft_timestomp" {
		t.Fatalf("FailedCollectors = %+v", v.FailedCollectors)
	}
}

func TestVerdictCleanScanIsLimpio(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("prefetch", art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil)),
	})
	if v.Level != report.LevelLimpio {
		t.Fatalf("Level = %q, want LIMPIO", v.Level)
	}
}

func TestVerdictCleanScanWithFailedCollectorIsIncompleto(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("prefetch", art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil)),
		{Collector: "mft_timestomp", Err: errors.New("acceso denegado")},
	})
	if v.Level != report.LevelIncompleto {
		t.Fatalf("un escaneo degradado sin hallazgos no puede ser LIMPIO, got %q", v.Level)
	}
}

func TestVerdictSuspiciousStaysSuspiciousWhenDegraded(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("mft", art("mft_timestomp", `C:\x.exe`, nil)),
		{Collector: "usn", Err: errors.New("acceso denegado")},
	})
	if v.Level != report.LevelSospechoso {
		t.Fatalf("la evidencia hallada no se degrada, got %q", v.Level)
	}
	if len(v.FailedCollectors) != 1 {
		t.Fatal("pero el fallo debe quedar listado para que el lector lo pondere")
	}
}

func TestVerdictCriticalIsEvidenciaFuerte(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("eventlog",
			art("eventlog.log_cleared", "Security", nil),
			art("mft_timestomp", `C:\x.exe`, nil),
		),
	})
	if v.Level != report.LevelEvidenciaFuerte {
		t.Fatalf("un cluster anti-forense es EVIDENCIA_FUERTE, got %q", v.Level)
	}
	if v.Summary == "" {
		t.Fatal("el veredicto necesita un resumen legible")
	}
	if len(v.Reasons) == 0 {
		t.Fatal("el veredicto debe enumerar por qué llegó a ese nivel")
	}
}

func TestVerdictTwoMediumsIsSospechoso(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("svc", art("service_driver", `C:\Temp\a.sys`, nil)),
		resultWith("sched", art("eventlog.desync", "Updater", nil)),
	})
	if v.Level != report.LevelSospechoso {
		t.Fatalf("dos MEDIUM son SOSPECHOSO, got %q", v.Level)
	}
}

func TestEvaluateEmptyInput(t *testing.T) {
	findings, v := Evaluate(nil)
	if len(findings) != 0 {
		t.Fatalf("sin resultados no hay hallazgos, got %+v", findings)
	}
	if v.Level != report.LevelLimpio {
		t.Fatalf("sin colectores caídos el nivel es LIMPIO, got %q", v.Level)
	}
}
```

- [ ] **Step 2: Correr los tests — deben fallar**

Run: `go test ./internal/verdict/`
Expected: FAIL de compilación — `undefined: evaluated`, `undefined: applyCombos`, `undefined: Evaluate`.

- [ ] **Step 3: Agregar los combos a `correlate.go`**

Agregar al final de `internal/verdict/correlate.go` (y sumar `"github.com/telagem/agent-windows/internal/report"` a sus imports):

```go
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
```

- [ ] **Step 4: Implementar `verdict.go`**

```go
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
```

- [ ] **Step 5: Correr los tests — deben pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/verdict/
git commit -m "feat: combos de co-ocurrencia y veredicto global del escaneo

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Cablear el motor en el runtime

**Files:**
- Modify: `internal/agent/agent.go`

**Interfaces:**
- Consumes: `verdict.Evaluate` (Task 6).
- Produces: `runWithCollectors` produce reportes con severidad y veredicto poblados.

- [ ] **Step 1: Reemplazar el bucle de findings**

En `internal/agent/agent.go`, agregar al bloque de imports:
```go
	"github.com/telagem/agent-windows/internal/verdict"
```

Reemplazar el bloque:
```go
	results := collector.Run(ctx, collectors)
	seq := 0
	for _, res := range results {
		findings := resultToFindings(res)
		for _, f := range findings {
			chainHash, err := chain.Append(f)
			if err != nil {
				continue
			}
			rep.Findings = append(rep.Findings, f)
			_ = up.StreamFinding(ctx, sess.SessionID, seq, f, chainHash)
			seq++
		}
	}
```
por:
```go
	results := collector.Run(ctx, collectors)
	findings, v := verdict.Evaluate(results)
	rep.Verdict = v
	seq := 0
	for _, f := range findings {
		chainHash, err := chain.Append(f)
		if err != nil {
			continue
		}
		rep.Findings = append(rep.Findings, f)
		_ = up.StreamFinding(ctx, sess.SessionID, seq, f, chainHash)
		seq++
	}
```

- [ ] **Step 2: Borrar `resultToFindings`**

Eliminar la función completa al final de `internal/agent/agent.go` (desde el comentario
`// resultToFindings traduce el resultado de un colector a findings.` hasta su llave de cierre).
Su responsabilidad pasó íntegra a `verdict.Evaluate`, que además la cubre con tests propios.

Verificar que el import de `fmt` siga usándose en el archivo (lo usa el error de
`no se pudo abrir sesión`), y que `report` y `collector` sigan importados.

- [ ] **Step 3: Correr la suite completa**

Run: `go test ./...`
Expected: PASS. En particular `internal/agent` debe seguir verde: el contrato de
`runWithCollectors` no cambió.

- [ ] **Step 4: Verificar build y vet cruzados a Windows**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./...`
Expected: sin advertencias.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/agent.go
git commit -m "feat: usar el motor de severidad en el runtime y retirar resultToFindings

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-review del plan

**Cobertura del spec:**

| Requisito del spec | Task |
|---|---|
| Tipo `Verdict` + campo en `Report` | 1 |
| Reglas base por tipo, tipo desconocido neutro | 2 |
| Escalado por contenido (dos niveles, tope HIGH) | 3 |
| Escalado por detalle (`hive_only`/`file_only`) | 3 |
| Colapso de evidencia neutra con conteo | 4 + 6 (orquestación en `Evaluate`) |
| Neutro sospechoso se emite individual y sigue contado | 6 (test explícito) |
| Extracción de tiempo por tipo, con tipos sin tiempo | 5 |
| Combo cluster anti-forense | 6 |
| Combo persistencia + logs borrados | 6 |
| Amplificador temporal de 30 min, tope 1.0 | 6 |
| Umbrales del veredicto global | 6 |
| `LIMPIO` + colector caído → `INCOMPLETO` | 6 (test explícito) |
| Niveles con evidencia no se degradan | 6 (test explícito) |
| `Evaluate` total ante datos corruptos | 3 y 5 (tests de `Data` corrupta) |
| Reemplazo de `resultToFindings` sin tocar el resto del flujo | 7 |

**Placeholders:** ninguno. Cada step tiene código completo y ejecutable.

**Consistencia de tipos:** `Rule` (Task 2) se consume con la misma forma en Tasks 3 y 6.
`evaluated` (Task 6) usa `finding`/`artType`/`at`/`hasTime` de forma idéntica en `applyCombos`,
en los tests y en `Evaluate`. `summaryFinding(collectorName string, total, emitted int)` (Task 4)
se invoca con esa misma firma en `Evaluate`. `timeOf` (Task 5) devuelve `(time.Time, bool)` y así
se consume en `Evaluate`. Las constantes `report.Level*` (Task 1) se usan con ese nombre en
Tasks 6.

**Nota sobre `isNeutral`:** se implementa como "no está en `baseRules`", de modo que los tipos
neutros conocidos (`prefetch`, `bam`, …) y los tipos futuros desconocidos comparten el mismo
camino. Es una sola fuente de verdad: agregar una regla a `baseRules` saca automáticamente al
tipo del colapso.

## Notas de cierre

- Tras Task 7 el agente deja de emitir todo como `INFO`: los reportes pasan a tener severidad,
  confianza y un veredicto global auditable.
- **Fuera de alcance** (ver spec): firmas de cheats por hash (`KNOWN_CHEAT`), detección de
  emuladores (`EMULATOR`), umbrales configurables por archivo y puntaje numérico agregado.
