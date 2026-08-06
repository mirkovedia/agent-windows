# Fase 6 — Interfaz de Escritorio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el `.exe` se abra con doble clic, se eleve solo, muestre una ventana propia con consentimiento, progreso en vivo del escaneo y resultados legibles — sin `.bat`, sin argumentos, sin consola.

**Architecture:** Una capa de presentación nueva (`internal/ui`) consume eventos que el runner emite mediante un `collector.Observer` opcional. La ventana es WebView2 con la interfaz embebida vía `go:embed` e inyectada con `SetHtml` — sin servidor HTTP local. La lógica forense de Fases 1–5 no se toca.

**Tech Stack:** Go 1.25+, `github.com/jchv/go-webview2` (pura Go, sin CGO), `golang.org/x/sys/windows` para la elevación UAC, HTML/CSS/JS embebidos.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, sin CGO (`CGO_ENABLED=0`). Verificado: `go-webview2` compila así.
- El `.exe` sigue siendo **un archivo único y portable**, sin instalador ni archivos acompañantes.
- **Cero sockets a la escucha**: la UI se inyecta con `SetHtml`, nunca con un servidor local.
- La lógica forense no cambia: colectores, motor de severidad y cadena de custodia quedan intactos.
- El modo consola actual sigue funcionando con `-console`.
- El consentimiento explícito se conserva: es la base legal de la herramienta.
- Código en inglés (identificadores); comentarios, textos de UI y commits en español.
- `Eval` desde una goroutine **siempre** va envuelto en `Dispatch`.

## Estructura de archivos

```
internal/collector/runner.go     MODIFICAR  Observer + RunObserved            — Task 1
internal/agent/agent.go          MODIFICAR  Options.Observer                  — Task 1
internal/elevate/                NUEVO      auto-elevación UAC                — Task 2
internal/ui/events.go            NUEVO      tipo Event + serialización        — Task 3
internal/ui/assets.go            NUEVO      go:embed + ensamblado del HTML    — Task 3
internal/ui/assets/index.html    NUEVO      estructura de las 3 pantallas     — Task 3
internal/ui/assets/app.css       NUEVO      tema oscuro, badges, animaciones  — Task 3
internal/ui/assets/app.js        NUEVO      estado y render dinámico          — Task 3
internal/ui/ui.go                NUEVO      ventana, Bind/Eval, ciclo de vida — Task 4
cmd/agent/main.go                MODIFICAR  GUI por defecto, -console         — Task 4
```

---

### Task 1: Observer de progreso (cambio aditivo)

**Files:**
- Modify: `internal/collector/runner.go`
- Modify: `internal/agent/agent.go`
- Test: `internal/collector/runner_test.go`

**Interfaces:**
- Produces:
  - `type Observer struct { OnStart func(index, total int, name string); OnFinish func(index, total int, res Result) }`
  - `func RunObserved(ctx context.Context, collectors []Collector, obs Observer) []Result`
  - `func Run(ctx context.Context, collectors []Collector) []Result` (sin cambios de firma)
  - `agent.Options` gana el campo `Observer collector.Observer`

`index` es 1-based. `Run` delega en `RunObserved` con un `Observer{}` vacío, así que ningún llamador ni test existente cambia.

- [ ] **Step 1: Escribir el test que falla**

Agregar a `internal/collector/runner_test.go`:

```go
func TestRunObservedEmitsStartAndFinishInOrder(t *testing.T) {
	cols := []Collector{
		&fakeCollector{name: "uno", priority: PriorityVolatile},
		&fakeCollector{name: "dos", priority: PriorityDisk},
	}
	var seq []string
	obs := Observer{
		OnStart: func(index, total int, name string) {
			seq = append(seq, fmt.Sprintf("start:%d/%d:%s", index, total, name))
		},
		OnFinish: func(index, total int, res Result) {
			seq = append(seq, fmt.Sprintf("finish:%d/%d:%s", index, total, res.Collector))
		},
	}
	RunObserved(context.Background(), cols, obs)

	want := []string{
		"start:1/2:uno", "finish:1/2:uno",
		"start:2/2:dos", "finish:2/2:dos",
	}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("secuencia = %v, want %v", seq, want)
	}
}

func TestRunObservedWithNilCallbacksDoesNotPanic(t *testing.T) {
	cols := []Collector{&fakeCollector{name: "uno", priority: PriorityDisk}}
	// Observer vacío: ambos callbacks nil. No debe entrar en panic.
	res := RunObserved(context.Background(), cols, Observer{})
	if len(res) != 1 {
		t.Fatalf("esperaba 1 resultado, got %d", len(res))
	}
}
```

Si `fakeCollector` no existe en el paquete de test, definirlo:

```go
type fakeCollector struct {
	name     string
	priority int
	arts     []Artifact
	err      error
}

func (f *fakeCollector) Name() string  { return f.name }
func (f *fakeCollector) Priority() int { return f.priority }
func (f *fakeCollector) Collect(ctx context.Context) ([]Artifact, error) {
	return f.arts, f.err
}
```

Imports necesarios del archivo de test: `context`, `fmt`, `reflect`, `testing`.

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/collector/ -run TestRunObserved`
Expected: FAIL de compilación — `undefined: Observer`, `undefined: RunObserved`.

- [ ] **Step 3: Implementar en `runner.go`**

Reemplazar la función `Run` por:

```go
// Observer recibe el avance del escaneo. Cualquiera de sus campos puede ser
// nil: sirve para que una interfaz muestre progreso en vivo sin que los
// colectores sepan que existe.
type Observer struct {
	// OnStart se invoca antes de correr cada colector. index es 1-based.
	OnStart func(index, total int, name string)
	// OnFinish se invoca al terminar cada colector, con su resultado.
	OnFinish func(index, total int, res Result)
}

// Run ejecuta los colectores ordenados por prioridad ascendente. Un panic
// dentro de un colector se recupera y se traduce a Result.Err: un colector
// que falla nunca tumba el escaneo.
func Run(ctx context.Context, collectors []Collector) []Result {
	return RunObserved(ctx, collectors, Observer{})
}

// RunObserved es Run con notificaciones de avance.
func RunObserved(ctx context.Context, collectors []Collector, obs Observer) []Result {
	ordered := make([]Collector, len(collectors))
	copy(ordered, collectors)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority() < ordered[j].Priority()
	})

	total := len(ordered)
	results := make([]Result, 0, total)
	for i, c := range ordered {
		index := i + 1
		if obs.OnStart != nil {
			obs.OnStart(index, total, c.Name())
		}
		res := runOne(ctx, c)
		if obs.OnFinish != nil {
			obs.OnFinish(index, total, res)
		}
		results = append(results, res)
	}
	return results
}
```

- [ ] **Step 4: Cablear en `agent.go`**

En `internal/agent/agent.go`, agregar el campo a `Options`:

```go
	// Observer, si tiene callbacks, recibe el avance del escaneo. El modo
	// consola lo deja vacío y se comporta exactamente como antes.
	Observer collector.Observer
```

Y en `runWithCollectors`, reemplazar:
```go
	results := collector.Run(ctx, collectors)
```
por:
```go
	results := collector.RunObserved(ctx, collectors, opts.Observer)
```

- [ ] **Step 5: Correr la suite completa**

Run: `go test ./...`
Expected: PASS. Los tests existentes de `internal/agent` y `internal/collector` no cambian.

- [ ] **Step 6: Commit**

```bash
git add internal/collector/ internal/agent/agent.go
git commit -m "feat: observer de progreso opcional en el runner de colectores

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Auto-elevación UAC

**Files:**
- Create: `internal/elevate/elevate_windows.go`
- Create: `internal/elevate/elevate_other.go`
- Test: `internal/elevate/elevate_test.go`

**Interfaces:**
- Produces:
  - `func Relaunch() error` — relanza el ejecutable actual pidiendo elevación
  - `var ErrUnsupported = errors.New("elevación solo disponible en Windows")`

`Relaunch` no retorna en el camino feliz desde el punto de vista del usuario: el llamador debe salir con `os.Exit(0)` inmediatamente después, porque la instancia elevada es un proceso nuevo.

- [ ] **Step 1: Escribir el test**

`internal/elevate/elevate_test.go`:

```go
package elevate

import (
	"errors"
	"testing"
)

// TestErrUnsupportedExists garantiza que el stub de no-Windows expone el
// error, para que el llamador pueda distinguir "no puedo elevar acá" de un
// fallo real de elevación.
func TestErrUnsupportedExists(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported no debe ser nil")
	}
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("ErrUnsupported debe ser comparable con errors.Is")
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/elevate/`
Expected: FAIL — el paquete no existe.

- [ ] **Step 3: Implementar el stub de no-Windows**

`internal/elevate/elevate_other.go`:

```go
//go:build !windows

package elevate

import "errors"

// ErrUnsupported indica que la elevación no está disponible en esta plataforma.
var ErrUnsupported = errors.New("elevación solo disponible en Windows")

// Relaunch no está soportado fuera de Windows.
func Relaunch() error { return ErrUnsupported }
```

- [ ] **Step 4: Implementar la versión de Windows**

`internal/elevate/elevate_windows.go`:

```go
//go:build windows

package elevate

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// ErrUnsupported existe para simetría con el stub de otras plataformas.
var ErrUnsupported = errors.New("elevación solo disponible en Windows")

// Relaunch vuelve a lanzar el ejecutable actual solicitando elevación (UAC).
// El proceso nuevo es independiente: el llamador debe terminar de inmediato
// con os.Exit(0) para no dejar dos instancias corriendo.
//
// Si el usuario rechaza el diálogo de UAC, Windows devuelve
// ERROR_CANCELLED y esta función retorna error.
func Relaunch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	// Se propagan los argumentos originales para que la instancia elevada
	// conserve el modo pedido (por ejemplo -console).
	args, err := windows.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	if err != nil {
		return err
	}
	cwd, err := windows.UTF16PtrFromString(filepathDir(exe))
	if err != nil {
		return err
	}
	// SW_NORMAL = 1: la ventana del proceso elevado se muestra normalmente.
	return windows.ShellExecute(0, verb, file, args, cwd, windows.SW_NORMAL)
}

// filepathDir evita importar path/filepath solo para una llamada.
func filepathDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}
```

- [ ] **Step 5: Verificar compilación cruzada y tests**

Run: `go test ./internal/elevate/`
Expected: PASS.
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./internal/elevate/`
Expected: compila.

- [ ] **Step 6: Commit**

```bash
git add internal/elevate/
git commit -m "feat: auto-elevacion UAC relanzando el ejecutable

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Eventos y assets embebidos

**Files:**
- Create: `internal/ui/events.go`
- Create: `internal/ui/assets.go`
- Create: `internal/ui/assets/index.html`
- Create: `internal/ui/assets/app.css`
- Create: `internal/ui/assets/app.js`
- Test: `internal/ui/events_test.go`
- Test: `internal/ui/assets_test.go`

**Interfaces:**
- Consumes: `collector.Result` (Task 1), `report.Report`.
- Produces:
  - `type Event struct { Kind, Collector, Error string; Index, Total, Artifacts int; Report *report.Report }`
  - Constantes `KindCollectorStart`, `KindCollectorDone`, `KindScanDone`, `KindScanError`
  - `func (e Event) JSON() (string, error)`
  - `func Page() string` — el HTML completo con CSS y JS embebidos

**Contrato Go↔JS (lo que fija esta task):**
- Go llama `window.onAgentEvent(<json>)` con un `Event` serializado.
- JS llama `window.startScan()` y `window.cancelScan()`, expuestas por `Bind` (Task 4).
- IDs de las tres pantallas: `#screen-consent`, `#screen-scan`, `#screen-results`.
- Clases de severidad para badges: `sev-info`, `sev-low`, `sev-medium`, `sev-high`, `sev-critical`.
- Clases de nivel de veredicto: `level-limpio`, `level-incompleto`, `level-sospechoso`, `level-evidencia_fuerte`.

- [ ] **Step 1: Escribir los tests que fallan**

`internal/ui/events_test.go`:

```go
package ui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEventJSONIncludesKind(t *testing.T) {
	e := Event{Kind: KindCollectorDone, Collector: "prefetch", Index: 3, Total: 11, Artifacts: 1247}
	raw, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("el evento debe ser JSON válido: %v", err)
	}
	if got["kind"] != KindCollectorDone {
		t.Fatalf("kind = %v", got["kind"])
	}
	if got["collector"] != "prefetch" {
		t.Fatalf("collector = %v", got["collector"])
	}
}

func TestEventJSONOmitsEmptyFields(t *testing.T) {
	e := Event{Kind: KindScanError, Error: "algo falló"}
	raw, _ := e.JSON()
	if strings.Contains(raw, `"collector"`) {
		t.Fatalf("los campos vacíos no deben serializarse: %s", raw)
	}
}

func TestEventKindsAreDistinct(t *testing.T) {
	kinds := map[string]bool{
		KindCollectorStart: true, KindCollectorDone: true,
		KindScanDone: true, KindScanError: true,
	}
	if len(kinds) != 4 {
		t.Fatalf("los cuatro kinds deben ser distintos, got %d", len(kinds))
	}
}
```

`internal/ui/assets_test.go`:

```go
package ui

import (
	"strings"
	"testing"
)

// TestPageInlinesAssets verifica que el HTML servido sea autocontenido: sin
// esto la ventana quedaría sin estilos ni lógica, porque SetHtml no resuelve
// referencias a archivos externos.
func TestPageInlinesAssets(t *testing.T) {
	page := Page()
	if !strings.Contains(page, "<style>") {
		t.Error("el CSS debe quedar embebido en una etiqueta <style>")
	}
	if !strings.Contains(page, "<script>") {
		t.Error("el JS debe quedar embebido en una etiqueta <script>")
	}
	if strings.Contains(page, `href="app.css"`) || strings.Contains(page, `src="app.js"`) {
		t.Error("no deben quedar referencias a archivos externos")
	}
}

func TestPageHasTheThreeScreens(t *testing.T) {
	page := Page()
	for _, id := range []string{"screen-consent", "screen-scan", "screen-results"} {
		if !strings.Contains(page, id) {
			t.Errorf("falta la pantalla %q", id)
		}
	}
}

func TestPageExposesEventEntryPoint(t *testing.T) {
	// El backend empuja eventos llamando a esta función global.
	if !strings.Contains(Page(), "onAgentEvent") {
		t.Error("la UI debe exponer window.onAgentEvent")
	}
}
```

- [ ] **Step 2: Correr los tests — deben fallar**

Run: `go test ./internal/ui/`
Expected: FAIL — el paquete no existe.

- [ ] **Step 3: Implementar `events.go`**

```go
// internal/ui/events.go

// Package ui es la capa de presentación del agente: una ventana WebView2 con
// la interfaz embebida. La lógica forense no depende de este paquete.
package ui

import (
	"encoding/json"

	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// Tipos de evento que el backend empuja a la interfaz.
const (
	KindCollectorStart = "collector_start"
	KindCollectorDone  = "collector_done"
	KindScanDone       = "scan_done"
	KindScanError      = "scan_error"
)

// Event es lo que la UI recibe durante el ciclo de vida del escaneo.
type Event struct {
	Kind      string         `json:"kind"`
	Collector string         `json:"collector,omitempty"`
	Index     int            `json:"index,omitempty"`
	Total     int            `json:"total,omitempty"`
	Artifacts int            `json:"artifacts,omitempty"`
	Error     string         `json:"error,omitempty"`
	Report    *report.Report `json:"report,omitempty"`
}

// JSON serializa el evento para pasarlo a JavaScript.
func (e Event) JSON() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
```

**Nota sobre el import:** si el módulo todavía se llama `github.com/telagem/agent-windows`,
usar ese path. El renombrado quedó a medias y no es parte de esta fase.

- [ ] **Step 4: Implementar `assets.go`**

```go
// internal/ui/assets.go
package ui

import (
	_ "embed"
	"strings"
)

//go:embed assets/index.html
var indexHTML string

//go:embed assets/app.css
var appCSS string

//go:embed assets/app.js
var appJS string

// Page devuelve el documento HTML completo, con el CSS y el JS embebidos.
// Se arma en memoria porque SetHtml no resuelve archivos externos: la página
// tiene que ser autocontenida o la ventana queda sin estilos ni lógica.
func Page() string {
	page := strings.Replace(indexHTML, "<!--INLINE_CSS-->", "<style>"+appCSS+"</style>", 1)
	page = strings.Replace(page, "<!--INLINE_JS-->", "<script>"+appJS+"</script>", 1)
	return page
}
```

- [ ] **Step 5: Escribir los assets**

`assets/index.html` debe contener, como mínimo: los marcadores `<!--INLINE_CSS-->` en el `<head>`
y `<!--INLINE_JS-->` antes de cerrar `<body>`, y las tres secciones con los ids
`screen-consent`, `screen-scan` y `screen-results`. Solo una pantalla visible a la vez
(clase `active`).

`assets/app.css` define el tema oscuro (fondo `#0f1116`, texto `#e6e8ee`, acento `#4c8dff`), las
clases de severidad (`sev-info` gris, `sev-low` azul, `sev-medium` ámbar, `sev-high` naranja,
`sev-critical` rojo), las de nivel de veredicto, la barra de progreso y las transiciones.

`assets/app.js` mantiene el estado y expone:

```js
// Punto de entrada que el backend invoca por cada evento.
window.onAgentEvent = function (json) { /* despacha por event.kind */ };
```

y llama a `window.startScan()` cuando el usuario acepta el consentimiento.
Al recibir `scan_done`, renderiza el veredicto y agrupa los hallazgos por `category`,
ordenados por severidad descendente, con los `INFO` colapsados por defecto.

- [ ] **Step 6: Correr los tests — deben pasar**

Run: `go test ./internal/ui/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/ui/
git commit -m "feat: eventos de UI y assets embebidos de la interfaz

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Ventana WebView2 y cableado en main

**Files:**
- Create: `internal/ui/ui.go`
- Modify: `cmd/agent/main.go`

**Interfaces:**
- Consumes: `Page()`, `Event` (Task 3); `collector.Observer` y `agent.Options.Observer` (Task 1); `elevate.Relaunch` (Task 2).
- Produces: `func Run(opts Options) error` y `type Options struct { Title string; OnScan func(emit func(Event)) }`

`OnScan` recibe una función `emit` ya envuelta en `Dispatch`: el llamador puede invocarla desde
cualquier goroutine sin preocuparse por el hilo de UI.

- [ ] **Step 1: Implementar `ui.go`**

```go
//go:build windows

// internal/ui/ui.go
package ui

import (
	"sync"

	webview "github.com/jchv/go-webview2"
)

// Options configura la ventana.
type Options struct {
	Title string
	// OnScan se ejecuta en una goroutine cuando el usuario acepta el
	// consentimiento. emit ya está envuelta en Dispatch: es seguro llamarla
	// desde cualquier goroutine.
	OnScan func(emit func(Event))
}

// Run abre la ventana y bloquea hasta que el usuario la cierra.
// Debe llamarse desde el hilo principal con runtime.LockOSThread() activo:
// WebView2 exige que la UI viva siempre en el mismo hilo del sistema.
func Run(opts Options) error {
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  opts.Title,
			Width:  1100,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		return ErrWebViewUnavailable
	}
	defer w.Destroy()

	// emit serializa el evento y lo empuja a JS en el hilo de UI.
	emit := func(e Event) {
		payload, err := e.JSON()
		if err != nil {
			return
		}
		w.Dispatch(func() {
			w.Eval("window.onAgentEvent(" + payload + ")")
		})
	}

	var once sync.Once
	if err := w.Bind("startScan", func() {
		// once evita que un doble clic dispare dos escaneos concurrentes.
		once.Do(func() {
			go opts.OnScan(emit)
		})
	}); err != nil {
		return err
	}
	if err := w.Bind("closeApp", func() {
		w.Terminate()
	}); err != nil {
		return err
	}

	w.SetHtml(Page())
	w.Run()
	return nil
}
```

Y en un archivo aparte `internal/ui/ui_errors.go` (sin build tag, para que el error exista en
cualquier plataforma):

```go
package ui

import "errors"

// ErrWebViewUnavailable indica que no se pudo crear la ventana, casi siempre
// porque falta el runtime de WebView2. El llamador debe degradar a consola.
var ErrWebViewUnavailable = errors.New("no se pudo iniciar WebView2")
```

Y un stub `internal/ui/ui_other.go`:

```go
//go:build !windows

package ui

// Run no está soportado fuera de Windows.
func Run(opts Options) error { return ErrWebViewUnavailable }

// Options configura la ventana.
type Options struct {
	Title  string
	OnScan func(emit func(Event))
}
```

**Cuidado:** `Options` se declara en el archivo de Windows y en el stub; deben estar en archivos
mutuamente excluyentes por build tag para no duplicar el tipo.

- [ ] **Step 2: Cablear `main.go`**

El flujo nuevo, respetando el modo consola:

```go
func main() {
	runtime.LockOSThread() // WebView2 exige hilo de UI fijo

	consoleMode := flag.Bool("console", false, "usar el modo consola en vez de la interfaz")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout global del escaneo")
	serverURL := flag.String("server", "", "URL base del servidor de verificación")
	outPath := flag.String("out", "", "ruta donde escribir el reporte localmente")
	flag.Parse()

	elevated, err := privilege.IsElevated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo verificar la elevación: %v\n", err)
		os.Exit(2)
	}
	if !elevated {
		// Relanzarse pidiendo UAC en vez de rendirse con un mensaje.
		if err := elevate.Relaunch(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: se requieren privilegios de administrador: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0) // la instancia elevada toma el control
	}

	if *consoleMode {
		runConsole(*timeout, *serverURL, *outPath)
		return
	}
	if err := runGUI(*timeout, *outPath); err != nil {
		// Sin WebView2 no se puede fallar en silencio: degradar a consola.
		fmt.Fprintf(os.Stderr, "No se pudo abrir la interfaz (%v).\n"+
			"Instalá el runtime de WebView2 o ejecutá con -console.\n", err)
		os.Exit(1)
	}
}
```

`runConsole` contiene el cuerpo actual de `main` (consentimiento por stdin + `agent.RunLive`),
extraído tal cual. `runGUI` arma las `Options` de UI:

```go
func runGUI(timeout time.Duration, outPath string) error {
	if outPath == "" {
		// Por defecto el reporte queda junto al ejecutable: el usuario no
		// tiene que pasar argumentos para que la app sea útil.
		exe, err := os.Executable()
		if err == nil {
			outPath = filepath.Join(filepath.Dir(exe), "reporte.json")
		} else {
			outPath = "reporte.json"
		}
	}
	return ui.Run(ui.Options{
		Title: "Mirkkkov PC — Verificación forense",
		OnScan: func(emit func(ui.Event)) {
			opts := agent.Options{
				Timeout: timeout,
				Version: agentVersion,
				Machine: machineInfo(true),
				Observer: collector.Observer{
					OnStart: func(i, total int, name string) {
						emit(ui.Event{Kind: ui.KindCollectorStart, Index: i, Total: total, Collector: name})
					},
					OnFinish: func(i, total int, res collector.Result) {
						ev := ui.Event{
							Kind: ui.KindCollectorDone, Index: i, Total: total,
							Collector: res.Collector, Artifacts: len(res.Artifacts),
						}
						if res.Err != nil {
							ev.Error = res.Err.Error()
						}
						emit(ev)
					},
				},
			}
			rep, err := agent.RunLive(context.Background(), opts, transport.NewLocalUploader(outPath))
			if err != nil {
				emit(ui.Event{Kind: ui.KindScanError, Error: err.Error()})
				return
			}
			emit(ui.Event{Kind: ui.KindScanDone, Report: &rep})
		},
	})
}
```

`machineInfo(elevated bool)` extrae el armado de `report.MachineInfo` que hoy está inline en
`main`, para que consola y GUI lo compartan.

**Nota:** el consentimiento en modo GUI lo da el usuario en la pantalla `screen-consent`, y
`startScan` solo se invoca después de aceptar. `agent.RunLive` recibe el consentimiento ya
otorgado, igual que hoy en el modo consola.

- [ ] **Step 3: Verificar build, vet y suite**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila.
Run: `GOOS=windows GOARCH=amd64 go vet ./...`
Expected: sin advertencias.
Run: `go test ./...`
Expected: PASS.

- [ ] **Step 4: Compilar el binario y validar a mano**

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o mirkkkov.exe ./cmd/agent
```

Validación manual (no automatizable): doble clic en `mirkkkov.exe` → UAC → ventana →
consentimiento → progreso en vivo → resultados.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/ cmd/agent/main.go
git commit -m "feat: ventana WebView2 con progreso en vivo y auto-elevacion

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-review del plan

**Cobertura del spec:**

| Requisito del spec | Task |
|---|---|
| Callback de progreso aditivo | 1 |
| Modo consola intacto | 1 (Observer vacío) y 4 (`-console`) |
| Auto-elevación UAC | 2 |
| Fallback si el UAC se rechaza | 2 + 4 |
| Tipo `Event` y serialización | 3 |
| Assets embebidos, HTML autocontenido | 3 |
| Sin servidor HTTP local | 3 (`SetHtml`) |
| Tres pantallas | 3 |
| Colores por nivel de veredicto y severidad | 3 (clases CSS) |
| Ventana WebView2 + puente | 4 |
| `Eval` siempre vía `Dispatch` | 4 (`emit`) |
| Fallback si falta WebView2 | 4 (`ErrWebViewUnavailable`) |
| Reporte a disco por defecto | 4 (`runGUI`) |
| Cancelación al cerrar la ventana | 4 (el proceso termina con la ventana) |

**Placeholders:** el contenido visual de `app.css`/`app.js`/`index.html` se especifica por
contrato (ids, clases, punto de entrada) y no línea por línea. Es deliberado: lo que debe quedar
fijo es la **interfaz entre Go y JS**, que es donde un error rompe el sistema. El markup exacto es
detalle de implementación y se valida a ojo.

**Consistencia de tipos:** `Event` (Task 3) se consume con los mismos campos en Task 4.
`collector.Observer` (Task 1) se usa con la misma forma en `runGUI`. `ui.Options.OnScan` recibe
`func(Event)` en la declaración y en el uso.

**Riesgo conocido:** `Options` se declara en `ui.go` (build tag windows) y en `ui_other.go`
(build tag !windows). Si ambos archivos quedan sin tag o con el mismo, el tipo se duplica y no
compila. El Step 3 de la Task 4 lo detecta de inmediato.

## Notas de cierre

- **Fuera de alcance** (ver spec): release público con tag, validación pendiente de Fase 5, y
  botón de "abrir carpeta".
- El renombrado del módulo sigue a medias (`telagem/agent-windows` en `go.mod` e imports). Los
  imports de esta fase deben usar el path que exista en el momento de implementar.
