# Fase 5 — Calibración de Falsos Positivos Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el agente, corrido sobre una máquina Windows limpia, emita veredicto `LIMPIO` en vez de `EVIDENCIA_FUERTE`, corrigiendo los detectores que alimentan al motor de severidad sin rediseñar el motor.

**Architecture:** Tres cambios acotados: matcheo de nombres en dos niveles (substring para marcadores inequívocos, token exacto para los ambiguos) más una allowlist de componentes WinSxS en `fsforensic`; tres reglas de detalle que bajan a `INFO` señales comunes en máquinas limpias en `verdict/escalate.go`; y deduplicación por `(tipo, ruta)` en `verdict.Evaluate`. Ningún colector cambia su lógica de recolección.

**Tech Stack:** Go 1.25+, solo stdlib (`strings`, `unicode`, `fmt`, `encoding/json`).

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, sin CGO (`CGO_ENABLED=0`).
- Sin dependencias externas nuevas.
- Ningún archivo de esta fase lleva build tag: todo es puro y se testea en cualquier host.
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Los tests usan **los nombres reales** extraídos del reporte del 2026-07-31, no fixtures inventados.
- `Evaluate` sigue siendo una función total: nunca devuelve error ni entra en panic.

## Estructura de archivos

```
internal/winfs/fsforensic/fsforensic.go   (modificar) tokenize, dos niveles de marcador, IsSystemComponent — Task 1
internal/verdict/escalate.go              (modificar) reglas de detalle desync/tarea/driver          — Task 2
internal/verdict/verdict.go               (modificar) deduplicación por (tipo, Source)               — Task 3
```

---

### Task 1: Matcheo en dos niveles y componentes de sistema (`fsforensic`)

**Files:**
- Modify: `internal/winfs/fsforensic/fsforensic.go`
- Modify: `internal/winfs/fsforensic/fsforensic_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func IsSuspiciousName(name string) bool` (misma firma, semántica corregida)
  - `func IsSystemComponent(name string) bool` (nueva)
  - `func tokenize(name string) []string` (no exportada)

- [ ] **Step 1: Escribir los tests que fallan**

Reemplazar el contenido de `internal/winfs/fsforensic/fsforensic_test.go` por:

```go
package fsforensic

import (
	"reflect"
	"testing"
)

func TestHasForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"cheat.exe":      true,
		"driver.SYS":     true,
		"script.ps1":     true,
		"documento.docx": false,
		"foto.jpg":       false,
		"sinextension":   false,
	}
	for name, want := range cases {
		if got := HasForensicExtension(name); got != want {
			t.Errorf("HasForensicExtension(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"logUploaderSettings.ini", []string{"log", "uploader", "settings", "ini"}},
		{"FreeFire_Injector.exe", []string{"free", "fire", "injector", "exe"}},
		{"pyproject-hooks.rkyv", []string{"pyproject", "hooks", "rkyv"}},
		{"esp.dll", []string{"esp", "dll"}},
	}
	for _, c := range cases {
		if got := tokenize(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tokenize(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestIsSuspiciousNameRealFalsePositives usa los nombres exactos que la
// primera ejecución real (2026-07-31) clasificó mal sobre una máquina limpia.
func TestIsSuspiciousNameRealFalsePositives(t *testing.T) {
	limpios := []string{
		// El único CRITICAL del reporte: caché del gestor de paquetes uv.
		"pyproject-hooks.rkyv",
		// Los 767 MEDIUM de USN.
		"logUploaderSettings.ini",
		"logUploaderSettings_temp.ini",
		"gamingservicesproxy_11.dll",
		// Manifiestos WinSxS: los 83 HIGH.
		"amd64_microsoft-windows-k..s-loader-deployment_31bf3856ad364e35_10.0.26100.8972_none_ffe303a9132d3dcd.manifest",
		"amd64_microsoft-windows-i..derninjectionbroker_31bf3856ad364e35_10.0.26100.8972_none_dbaeabf8478efa20.manifest",
		"amd64_microsoft-onecore-m..lnamespaceextension_31bf3856ad364e35_10.0.26100.8972_none_691608c8ce3ff087.manifest",
		"amd64_microsoft-windows-c..ore-earlydownloader_31bf3856ad364e35_10.0.26100.8972_none_61dae73cb281a585.manifest",
		"amd64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35_10.0.26100.8972_none_6a0e0ddc1e647f95.manifest",
		"amd64_microsoft-onecore-w..hreatresponseengine_31bf3856ad364e35_10.0.26100.8972_none_5af092601200b56e.manifest",
		"amd64_microsoft-windows-s..agespaces-spaceutil_31bf3856ad364e35_10.0.26100.8972_none_77f71f2e7f54f72f.manifest",
		// Nombres normales.
		"notepad.exe",
		"informe.docx",
	}
	for _, n := range limpios {
		if IsSuspiciousName(n) {
			t.Errorf("IsSuspiciousName(%q) = true, es un archivo legítimo", n)
		}
	}
}

func TestIsSuspiciousNameStillDetects(t *testing.T) {
	sospechosos := []string{
		"FreeFire_Injector.exe", // token "injector"
		"aimbot_loader.exe",     // marcador fuerte "aimbot"
		"aimbotloader.exe",      // fuerte, sin separadores
		"esp.dll",               // token exacto "esp"
		"cheat.exe",             // fuerte
		"CCleaner.exe",          // fuerte
		"hook.dll",              // token exacto "hook"
		"macro_v2.ahk",          // token exacto "macro"
	}
	for _, n := range sospechosos {
		if !IsSuspiciousName(n) {
			t.Errorf("IsSuspiciousName(%q) = false, debería detectarse", n)
		}
	}
}

func TestIsSystemComponent(t *testing.T) {
	componentes := []string{
		"amd64_microsoft-windows-k..s-loader-deployment_31bf3856ad364e35_10.0.26100.8972_none_ffe303a9132d3dcd.manifest",
		"wow64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35_10.0.26100.8972_none_7462b82e52c54190.manifest",
	}
	for _, n := range componentes {
		if !IsSystemComponent(n) {
			t.Errorf("IsSystemComponent(%q) = false, es un componente WinSxS", n)
		}
	}
	normales := []string{"notepad.exe", "aimbot.exe", "microsoft-word.docx"}
	for _, n := range normales {
		if IsSystemComponent(n) {
			t.Errorf("IsSystemComponent(%q) = true, no es un componente WinSxS", n)
		}
	}
}
```

- [ ] **Step 2: Correr los tests — deben fallar**

Run: `go test ./internal/winfs/fsforensic/`
Expected: FAIL — `undefined: tokenize`, `undefined: IsSystemComponent`, y los falsos positivos reales todavía dan `true`.

- [ ] **Step 3: Reescribir `fsforensic.go`**

Reemplazar el contenido completo de `internal/winfs/fsforensic/fsforensic.go` por:

```go
package fsforensic

import (
	"path/filepath"
	"strings"
	"unicode"
)

// forensicExts son las extensiones de ejecutables/scripts que se retienen.
var forensicExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".bat": true, ".ps1": true,
	".cmd": true, ".vbs": true, ".scr": true, ".msi": true,
}

// strongMarkers son marcadores largos e inequívocos: ninguna palabra legítima
// los contiene, así que se buscan como substring. Eso los hace robustos frente
// a nombres sin separadores ("aimbotloader.exe").
var strongMarkers = []string{"cheat", "aimbot", "ccleaner", "bleachbit"}

// weakMarkers son marcadores cortos o frecuentes como fragmento de palabras
// legítimas, así que solo cuentan como token completo. Buscarlos por substring
// producía falsos positivos masivos: "esp" matchea "response" y "namespace",
// "loader" matchea "uploader" y "downloader", "hook" matchea "pyproject-hooks".
// "injector" figura aparte de "inject" porque el matcheo es de token exacto.
var weakMarkers = []string{
	"inject", "injector", "loader", "bypass", "macro", "esp", "hook", "wipe",
}

// msPublicKeyToken es el token de clave pública de Microsoft presente en el
// nombre de todo componente del almacén WinSxS.
const msPublicKeyToken = "_31bf3856ad364e35_"

// winsxsPrefixes son los prefijos de arquitectura del almacén de componentes.
var winsxsPrefixes = []string{
	"amd64_microsoft-", "wow64_microsoft-", "x86_microsoft-", "msil_microsoft-",
}

// HasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func HasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// IsSystemComponent reporta si el nombre corresponde a un componente del
// almacén WinSxS de Windows. Windows Update borra y reemplaza estos archivos de
// forma rutinaria, y sus nombres contienen palabras como "loader", "inject" o
// "hook" por motivos legítimos.
//
// Se identifica por el nombre y no por la ruta a propósito: la reconstrucción
// del directorio padre desde el MFT falla a menudo (rutas "<sin-resolver>"),
// así que una allowlist por ruta no los alcanzaría.
func IsSystemComponent(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, msPublicKeyToken) {
		return true
	}
	for _, p := range winsxsPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// IsSuspiciousName reporta si el nombre contiene un marcador sospechoso.
// Los componentes de sistema quedan excluidos sin evaluar marcadores.
func IsSuspiciousName(name string) bool {
	if IsSystemComponent(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, m := range strongMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	tokens := tokenize(name)
	for _, tk := range tokens {
		for _, m := range weakMarkers {
			if tk == m {
				return true
			}
		}
	}
	return false
}

// tokenize parte un nombre de archivo en tokens en minúscula, cortando por
// separadores (-, _, ., espacio) y por cambios de camelCase. Así
// "logUploaderSettings.ini" da [log uploader settings ini] y el marcador
// "loader" deja de matchear "Uploader".
func tokenize(name string) []string {
	var tokens []string
	var cur []rune

	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '-' || r == '_' || r == '.' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]):
			// Frontera camelCase: "logUploader" -> "log" + "Uploader".
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return tokens
}
```

- [ ] **Step 4: Correr los tests — deben pasar**

Run: `go test ./internal/winfs/fsforensic/`
Expected: PASS.

- [ ] **Step 5: Correr la suite completa**

Run: `go test ./...`
Expected: PASS. `fsforensic` lo usan los colectores `usn`, `deleted`, `mft` y `scheduler`; sus
tests deben seguir verdes.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/fsforensic/
git commit -m "fix: matcheo de nombres en dos niveles y allowlist de componentes WinSxS

El matcheo por substring daba falsos positivos masivos: esp matchea
response y namespace, loader matchea uploader, hook matchea
pyproject-hooks. Los marcadores ambiguos pasan a token exacto.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Reglas de detalle que bajan a INFO (`verdict/escalate.go`)

**Files:**
- Modify: `internal/verdict/escalate.go`
- Modify: `internal/verdict/escalate_test.go`

**Interfaces:**
- Consumes: `Rule`, `SevInfo`, `SevMedium` (Fase 4); `collector.Artifact`.
- Produces: `escalateByDetail` maneja tres tipos más, además de `scheduled_task_desync`.

- [ ] **Step 1: Escribir los tests que fallan**

Agregar al final de `internal/verdict/escalate_test.go`:

```go
func TestEscalateTaskNoRegisterLogIsInfo(t *testing.T) {
	// Los Event Logs rotan: una tarea vieja nunca tiene su evento 106, así
	// que la ausencia no prueba nada. Se reporta pero no mueve el veredicto.
	a := art("eventlog.desync", "Updater", map[string]string{"Kind": "task_no_register_log"})
	got := escalate(a, ruleFor("eventlog.desync"))
	if got.Severity != SevInfo {
		t.Fatalf("task_no_register_log debe ser INFO, got %s", got.Severity)
	}
}

func TestEscalateOtherDesyncKindsStayMedium(t *testing.T) {
	for _, kind := range []string{"service_no_install_log", "service_installed_then_removed", "task_delete_desync"} {
		a := art("eventlog.desync", "X", map[string]string{"Kind": kind})
		got := escalate(a, ruleFor("eventlog.desync"))
		if got.Severity != SevMedium {
			t.Errorf("%s debe seguir en MEDIUM, got %s", kind, got.Severity)
		}
	}
}

func TestEscalateMicrosoftHiddenTaskIsInfo(t *testing.T) {
	a := art("scheduled_task", `Microsoft\Windows\UpdateOrchestrator\Reboot`,
		map[string]any{"RelPath": `Microsoft\Windows\UpdateOrchestrator\Reboot`, "Hidden": true})
	got := escalate(a, ruleFor("scheduled_task"))
	if got.Severity != SevInfo {
		t.Fatalf("una tarea oculta de Microsoft debe ser INFO, got %s", got.Severity)
	}
}

func TestEscalateNonMicrosoftHiddenTaskStaysMedium(t *testing.T) {
	a := art("scheduled_task", `MiTareaRara`,
		map[string]any{"RelPath": `MiTareaRara`, "Hidden": true})
	got := escalate(a, ruleFor("scheduled_task"))
	if got.Severity != SevMedium {
		t.Fatalf("una tarea oculta fuera de Microsoft sigue en MEDIUM, got %s", got.Severity)
	}
}

func TestEscalateDriverInNormalLocationIsInfo(t *testing.T) {
	normales := []string{
		`C:\Program Files\Vendor\driver.sys`,
		`C:\Program Files (x86)\Otro\x.sys`,
		`C:\Windows\System32\DriverStore\FileRepository\algo\y.sys`,
	}
	for _, p := range normales {
		a := art("service_driver", p, map[string]any{"ImagePath": p})
		got := escalate(a, ruleFor("service_driver"))
		if got.Severity != SevInfo {
			t.Errorf("driver en %q debe ser INFO, got %s", p, got.Severity)
		}
	}
}

func TestEscalateDriverInSuspiciousLocationStaysMedium(t *testing.T) {
	raros := []string{
		`C:\Users\X\AppData\Local\Temp\evil.sys`,
		`C:\Users\X\Downloads\d.sys`,
	}
	for _, p := range raros {
		a := art("service_driver", p, map[string]any{"ImagePath": p})
		got := escalate(a, ruleFor("service_driver"))
		if got.Severity != SevMedium {
			t.Errorf("driver en %q debe seguir en MEDIUM, got %s", p, got.Severity)
		}
	}
}
```

- [ ] **Step 2: Correr los tests — deben fallar**

Run: `go test ./internal/verdict/ -run TestEscalate`
Expected: FAIL — las nuevas reglas todavía no existen, los tipos quedan en su severidad base.

- [ ] **Step 3: Extender `escalateByDetail`**

En `internal/verdict/escalate.go`, reemplazar la función `escalateByDetail` completa por:

```go
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
```

Y agregar `"strings"` al bloque de imports del archivo.

- [ ] **Step 4: Correr los tests — deben pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/verdict/escalate.go internal/verdict/escalate_test.go
git commit -m "fix: bajar a INFO senales comunes en maquinas limpias

task_no_register_log no puede ser sana porque los Event Logs rotan;
Windows trae decenas de tareas ocultas propias; y los drivers en
Program Files o DriverStore son software instalado normal.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Deduplicación por (tipo, ruta) (`verdict/verdict.go`)

**Files:**
- Modify: `internal/verdict/verdict.go`
- Modify: `internal/verdict/verdict_test.go`

**Interfaces:**
- Consumes: `evaluated` (Fase 4).
- Produces: `Evaluate` colapsa artefactos repetidos.

- [ ] **Step 1: Escribir los tests que fallan**

Agregar al final de `internal/verdict/verdict_test.go`:

```go
func TestEvaluateDeduplicatesSameArtifact(t *testing.T) {
	// El USN registra cada modificación del archivo: el mismo objeto aparece
	// muchas veces y hoy cada evento produce un hallazgo separado.
	same := `C:\Temp\aimbot.exe`
	arts := []collector.Artifact{
		art("deleted_entry", same, nil),
		art("deleted_entry", same, nil),
		art("deleted_entry", same, nil),
	}
	findings, _ := Evaluate([]collector.Result{resultWith("deleted", arts...)})
	if len(findings) != 1 {
		t.Fatalf("tres eventos del mismo artefacto deben colapsar en 1, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "3") {
		t.Fatalf("la evidencia debe informar cuántos eventos hubo, got %q", findings[0].Evidence)
	}
}

func TestEvaluateDoesNotMergeDifferentArtifacts(t *testing.T) {
	arts := []collector.Artifact{
		art("deleted_entry", `C:\Temp\aimbot.exe`, nil),
		art("deleted_entry", `C:\Temp\cheat.exe`, nil),
	}
	findings, _ := Evaluate([]collector.Result{resultWith("deleted", arts...)})
	if len(findings) != 2 {
		t.Fatalf("artefactos distintos no se colapsan, got %d", len(findings))
	}
}

func TestEvaluateDoesNotMergeAcrossTypes(t *testing.T) {
	same := `C:\Temp\aimbot.exe`
	findings, _ := Evaluate([]collector.Result{
		resultWith("deleted", art("deleted_entry", same, nil)),
		resultWith("mft", art("mft_timestomp", same, nil)),
	})
	if len(findings) != 2 {
		t.Fatalf("el mismo archivo visto por dos detectores son dos señales, got %d", len(findings))
	}
}
```

Y agregar `"strings"` al bloque de imports de `verdict_test.go`.

- [ ] **Step 2: Correr los tests — deben fallar**

Run: `go test ./internal/verdict/ -run TestEvaluateDedup`
Expected: FAIL — hoy se emiten 3 hallazgos en vez de 1.

- [ ] **Step 3: Implementar la deduplicación**

En `internal/verdict/verdict.go`, dentro de `Evaluate`, declarar el mapa de conteo antes del bucle
sobre `results` (junto a `items`, `failed` y `summaries`):

```go
	// seen mapea (tipo de artefacto, Source) al índice en items del primer
	// hallazgo de ese objeto; dupCount cuenta cuántas veces se lo vio. El USN
	// registra cada modificación, así que un mismo archivo aparece N veces.
	type dedupKey struct{ artType, source string }
	seen := make(map[dedupKey]int)
	dupCount := make(map[dedupKey]int)
```

Reemplazar el bloque que hace `items = append(items, evaluated{...})` dentro del bucle de
artefactos por:

```go
			key := dedupKey{artType: a.Type, source: a.Source}
			dupCount[key]++
			if _, dup := seen[key]; dup {
				continue // ya se emitió un hallazgo para este objeto
			}
			at, hasTime := timeOf(a)
			seen[key] = len(items)
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
```

Y después del bucle sobre `results`, antes de `items = applyCombos(items)`, anotar los conteos:

```go
	// Anotar cuántos eventos respaldan cada hallazgo colapsado.
	for key, idx := range seen {
		if n := dupCount[key]; n > 1 {
			items[idx].finding.Evidence = fmt.Sprintf("%d eventos sobre este artefacto. %s",
				n, items[idx].finding.Evidence)
		}
	}
```

- [ ] **Step 4: Correr los tests — deben pasar**

Run: `go test ./internal/verdict/`
Expected: PASS.

- [ ] **Step 5: Verificar build, vet y suite completa**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./...`
Expected: sin advertencias.
Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/verdict/verdict.go internal/verdict/verdict_test.go
git commit -m "fix: deduplicar hallazgos del mismo artefacto

El USN registra cada modificacion de un archivo, asi que el mismo objeto
generaba decenas de hallazgos identicos. Se colapsan por (tipo, ruta) y
se anota el numero de eventos en la evidencia.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Validación contra la máquina real

**Files:**
- Ninguno (validación end-to-end).

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: confirmación empírica del criterio de éxito de la fase.

- [ ] **Step 1: Recompilar el binario**

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o mirkkkov.exe ./cmd/agent
```

- [ ] **Step 2: Re-ejecutar el escaneo**

El usuario ejecuta `ejecutar.bat` como administrador (o
`mirkkkov.exe -out reporte.json` desde una consola elevada).

- [ ] **Step 3: Comparar contra la línea base**

Línea base del 2026-07-31, antes de esta fase:

```
1070 hallazgos — 1 CRITICAL, 83 HIGH, 970 MEDIUM, 11 LOW, 5 INFO
Veredicto: EVIDENCIA_FUERTE
```

Criterio de éxito: **veredicto `LIMPIO`** sobre la misma máquina limpia.

Si aparecen falsos positivos nuevos, sus nombres se agregan como casos a
`TestIsSuspiciousNameRealFalsePositives` y se itera. El reporte real es la fuente de verdad de
esta fase, no los fixtures.

---

## Self-review del plan

**Cobertura del spec:**

| Requisito del spec | Task |
|---|---|
| Matcheo en dos niveles (fuerte substring / débil token) | 1 |
| `tokenize` con separadores y camelCase | 1 |
| `injector` como variante de token | 1 |
| `IsSystemComponent` por clave pública y prefijos WinSxS | 1 |
| `IsSuspiciousName` excluye componentes de sistema | 1 |
| `task_no_register_log` → INFO | 2 |
| Otras direcciones de desync sin cambios | 2 |
| Tareas ocultas bajo `Microsoft\` → INFO | 2 |
| Drivers en ubicaciones normales → INFO | 2 |
| Deduplicación por `(tipo, Source)` con conteo | 3 |
| Tests con nombres reales del reporte | 1, 2, 3 |
| Criterio de éxito: veredicto `LIMPIO` | 4 |

**Placeholders:** ninguno; cada step tiene código completo.

**Consistencia de tipos:** `escalateByDetail(a collector.Artifact, r Rule) Rule` conserva su firma
de Fase 4 y solo cambia su cuerpo, así que `escalate` no se toca. Las cuatro funciones nuevas
(`desyncTaskRule`, `eventDesyncRule`, `scheduledTaskRule`, `serviceDriverRule`) comparten esa misma
firma. `dedupKey` es local a `Evaluate`. `IsSystemComponent` es la única función exportada nueva.

**Nota sobre el orden de escalado:** `escalate` llama primero a `escalateByDetail` y después a
`escalateByName`. Un driver en `Program Files` baja a INFO por detalle, pero si además su nombre
matchea un marcador fuerte, `escalateByName` lo vuelve a subir. Es el comportamiento correcto: un
`Program Files\cheatengine\driver.sys` debe seguir destacándose.

## Notas de cierre

- Esta fase no rediseña el motor de severidad: corrige los detectores que lo alimentan.
- **Fuera de alcance** (ver spec): resolución de rutas `<sin-resolver>`, verificación Authenticode
  de drivers, y marcadores de detección nuevos.
