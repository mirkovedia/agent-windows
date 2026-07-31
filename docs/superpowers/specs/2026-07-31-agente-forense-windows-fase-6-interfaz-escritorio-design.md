# Agente Forense Windows — Fase 6: Interfaz de Escritorio (Design)

**Fecha:** 2026-07-31
**Estado:** Aprobado, listo para plan de implementación
**Depende de:** Fases 1–5 (11 colectores, motor de severidad, calibración)

## Contexto

Tras cinco fases el proyecto tiene un motor forense sólido y **ningún producto**. Para usarlo hay
que abrir una consola como administrador, pasarle flags, y después leer un JSON de 600 KB. El
usuario nunca vio la herramienta funcionando de forma presentable.

La referencia declarada es KellerSS: ventana propia con tema oscuro, hallazgos agrupados por
categoría, badges de color por severidad. Esa interfaz está hecha con HTML dentro de una ventana
de aplicación — igual que Discord, VS Code o Spotify. El usuario nunca ve un navegador.

## Objetivo

Que alguien baje un `.exe`, le haga doble clic, y **sin archivos acompañantes ni argumentos**
obtenga: elevación automática, una ventana propia, consentimiento explícito, el escaneo
avanzando en vivo, y los resultados legibles.

## Principio rector

**La lógica forense no sabe que existe una interfaz.** Todo lo de Fases 1–5 queda intacto: los
colectores, el motor de severidad y el flujo de custodia no se tocan. La UI es una capa de
presentación que consume eventos.

Corolario: el modo consola actual sigue funcionando. La GUI es el camino por defecto, no el único.

## Decisiones y sus costos

### Dependencia externa (excepción deliberada)

El proyecto venía cumpliendo "solo stdlib + `golang.org/x/sys`". Esta fase agrega
`github.com/jchv/go-webview2`. Verificado antes de diseñar:

- Es **pura Go**: compila con `CGO_ENABLED=0 GOOS=windows GOARCH=amd64`.
- El `.exe` sigue siendo un archivo único y portable.
- Arrastra una dependencia transitiva: `github.com/jchv/go-winloader`.

**Costo aceptado:** si el paquete queda sin mantenimiento, el mantenimiento es nuestro. Se acepta
porque no existe camino en la librería estándar hacia una interfaz moderna.

### Sin servidor HTTP local

La UI se inyecta con `WebView.SetHtml()`, con CSS y JS embebidos en un único string HTML
construido en tiempo de compilación vía `go:embed`.

La alternativa habitual (servidor en `127.0.0.1` + `Navigate`) se descarta a propósito: una
herramienta forense que abre un socket a la escucha es una herramienta más difícil de justificar
ante un antivirus o ante un jugador desconfiado. **Cero puertos abiertos.**

### Dependencia del runtime WebView2

WebView2 viene preinstalado en Windows 11 y se distribuyó por Windows Update en Windows 10 desde
2021. Es casi universal, pero **no garantizado**.

Si falta, el agente **no puede fallar en silencio**: cae al modo consola con un mensaje que explica
qué falta y dónde conseguirlo. Un escaneo que no arranca es peor que uno feo.

## Arquitectura

```
internal/ui/                 NUEVO — capa de presentación
  ui.go                      ventana WebView2, puente Go↔JS, ciclo de vida
  events.go                  tipos de evento backend→UI (JSON)
  assets/index.html          estructura de las tres pantallas
  assets/app.css             tema oscuro, badges, animaciones
  assets/app.js              estado y render dinámico
  assets.go                  go:embed + ensamblado del HTML único

internal/elevate/            NUEVO — auto-elevación
  elevate_windows.go         ShellExecuteW con verbo "runas"
  elevate_other.go           stub para compilar fuera de Windows

internal/agent/agent.go      MODIFICAR — callback de progreso opcional
internal/collector/          MODIFICAR — Run acepta callback opcional
cmd/agent/main.go            MODIFICAR — GUI por defecto, -console para el modo actual
```

### Flujo

```
main()
  ├─ runtime.LockOSThread()          WebView2 exige hilo de UI fijo
  ├─ ¿elevado?
  │    └─ no → elevate.Relaunch() → exit(0)   (UAC; la instancia vieja muere)
  ├─ ¿-console o WebView2 ausente?
  │    └─ sí → flujo de consola actual (sin cambios)
  └─ ui.Run()
       ├─ SetHtml(interfaz embebida)
       ├─ Bind("startScan")   ← JS llama cuando el usuario acepta
       ├─ Bind("cancelScan")
       └─ Run()  (bloquea hasta cerrar la ventana)

startScan (goroutine)
  └─ agent.RunLive(ctx, opts, uploader) con Progress callback
       └─ cada evento → w.Dispatch(func(){ w.Eval("window.onAgentEvent(...)") })
```

### El puente

`Bind(name, fn) error` expone funciones Go como globales de JavaScript. `Eval(js)` empuja hacia la
UI. `Dispatch(f)` garantiza que la actualización ocurra en el hilo de UI: **el escaneo corre en
una goroutine, así que toda llamada a `Eval` debe pasar por `Dispatch`**. Ignorar esto produce
cuelgues difíciles de diagnosticar.

### Eventos backend→UI

```go
// Event es lo que la UI recibe. Un solo tipo para todo el ciclo del escaneo.
type Event struct {
    Kind      string `json:"kind"`      // "collector_start" | "collector_done" | "scan_done" | "scan_error"
    Collector string `json:"collector,omitempty"`
    Index     int    `json:"index,omitempty"`     // colector actual (1..Total)
    Total     int    `json:"total,omitempty"`     // cantidad de colectores
    Artifacts int    `json:"artifacts,omitempty"` // recolectados por ese colector
    Error     string `json:"error,omitempty"`
    Report    any    `json:"report,omitempty"`    // solo en scan_done
}
```

### Callback de progreso (cambio aditivo)

`agent.Options` gana un campo opcional:

```go
// Progress, si no es nil, recibe un evento por cada transición de colector.
// El modo consola lo deja en nil y se comporta exactamente como antes.
Progress func(ui.Event)
```

`collector.Run` gana un parámetro de callback opcional. Ningún colector cambia.

## Las tres pantallas

**1. Consentimiento.** Es la base legal de toda la herramienta y no se toca: mismo texto que hoy
(`consent.CollectionSummary()`), reusado desde Go. Dos botones: Aceptar / Rechazar. Rechazar
cierra la app sin escanear.

**2. Escaneo.** Lista de los 11 colectores, cada uno con estado: *pendiente* → *escaneando…* →
*listo (N artefactos)* o *falló*. Barra de progreso general. Un colector que falla se marca en
ámbar y el escaneo continúa — refleja el invariante del runner.

**3. Resultados.** El veredicto arriba, grande y con color según nivel:

| Nivel | Color |
|---|---|
| `LIMPIO` | verde |
| `INCOMPLETO` | gris |
| `SOSPECHOSO` | ámbar |
| `EVIDENCIA_FUERTE` | rojo |

Debajo, los hallazgos agrupados por categoría en secciones colapsables, ordenados por severidad
descendente, cada uno con badge de color, título, ruta del artefacto y evidencia expandible. Los
`INFO` van colapsados por defecto: son la mayoría y son ruido para quien mira el resultado.

Además, un botón para copiar la ruta del reporte JSON, que se sigue escribiendo a disco como
constancia auditable.

## Manejo de errores

- **Sin elevación** → relanzar con UAC. Si el usuario rechaza el UAC, salir con mensaje claro.
- **WebView2 ausente** → fallback a consola explicando qué instalar.
- **Colector caído** → ya cubierto por el runner; la UI lo muestra en ámbar y sigue.
- **Escaneo con error fatal** → evento `scan_error`; la UI muestra el mensaje sin cerrarse.
- **Usuario cierra la ventana mientras escanea** → se cancela el `context`, el escaneo termina
  ordenadamente.

## Testing

La lógica testeable se aísla de la ventana, que no se puede testear automáticamente:

| Qué | Cómo |
|---|---|
| Ensamblado del HTML | Test puro: verifica que el HTML final contenga el CSS y el JS embebidos |
| Serialización de eventos | Test puro sobre `Event` → JSON con los campos esperados |
| Callback de progreso | `runWithCollectors` con colectores falsos: verifica la secuencia de eventos emitida |
| Modo consola intacto | Los tests existentes de `internal/agent` siguen verdes sin cambios |
| Ventana WebView2 | **No se testea automáticamente.** Validación manual, igual que el resto del `.exe` |

**Criterio de éxito:** doble clic en el `.exe` sobre una máquina limpia → UAC → ventana →
consentimiento → progreso en vivo → resultados legibles. Sin `.bat`, sin argumentos, sin consola.

## Fuera de alcance

- **Release público con tag** para descarga. Es la fase siguiente y es corta.
- **Validación pendiente de Fase 5** (llegar a veredicto `LIMPIO`). Esta interfaz la vuelve mucho
  más fácil: los hallazgos se ven agrupados en vez de buscarse en un JSON de 600 KB.
- Botón "abrir carpeta del archivo": el motor de WebView no puede abrir el explorador por
  seguridad. Se resuelve copiando la ruta.
- Internacionalización: la interfaz va en español, como el resto del producto.
