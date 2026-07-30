# Agente Forense Windows — Fase 3D: Event Logs (.evtx) (Design)

**Fecha:** 2026-07-30
**Estado:** Implementado (7/7 tasks, mergeado a master el 2026-07-30)
**Depende de:** Fases 1-3C (interfaz `collector.Collector`, `wintext.DecodeUTF16`, `wintime`,
patrón VSS, patrón de build tags `winfs/*`, parsers puros `winfs/services` y `winfs/scheduler`,
patrón de builder sintético `reghivetest`)

## Contexto

El agente forense por consentimiento (telagem/screenshare) reconstruye qué se ejecutó y qué se
borró en la máquina de un jugador de Free Fire. Las Fases 1-3C cubrieron evidencia de *ejecución*
(Prefetch, BAM, ShimCache, AmCache), de *borrado/manipulación* (USN Journal, timestomping SI vs FN,
recuperación cruda de entradas MFT borradas) y de *persistencia* (servicios no estándar, tareas
programadas con cross-check XML↔TaskCache).

Comparando contra la herramienta de referencia de la comunidad (KellerSS-PC), se decidió que la
identidad del agente es **cheat-scanner con paridad KellerSS pero con más rigor**. El gap #1 en
valor es el módulo de **Event Logs**: KellerSS inspecciona patrones de login (AuthModule), Event
Logs y localhost, pero no razona sobre manipulación de bajo nivel de los propios logs. El borrado
de logs es una señal directa de tampering — el eje donde este agente ya es superior.

Esta fase es el arranque de un roadmap de paridad con KellerSS. Las fases siguientes (fuera de este
spec) son: 3E (firmas de cheats + análisis de strings/imports), 3F (PCA, crash dumps, temp
folders), 3G (hosts/localhost + sustitución de disco).

## Objetivo

Detectar y reportar, leyendo `Security.evtx`, `System.evtx` y
`Microsoft-Windows-TaskScheduler%4Operational.evtx` desde un snapshot VSS:

1. **Timeline de sesión** — reconstrucción de arranques/apagados (`6005`/`6006`/`6008`) y
   logon/logoff (`4624`/`4634`) con logon type resuelto (2=interactivo, 3=red, 10=RDP). Establece
   la ventana de análisis del escaneo.
2. **Borrado de logs** — eventos `1102` (Security audit cleared) y `104` (cualquier log limpiado),
   con la cuenta que lo ejecutó cuando el propio evento sobrevive. Señal directa de tampering.
3. **Señales de tampering de bajo nivel** — gaps en el número de record (registros borrados), CRC32
   de chunk inválido (manipulación directa del archivo), flags dirty/full (cierre sucio),
   truncado.
4. **Desincronización cross-colector** — cross-check de eventos `7045` (instalación de servicio)
   contra el estado actual del registro (`winfs/services`, desde `System.evtx`) y de eventos de
   TaskScheduler (`106`/`140`/`141`, desde el canal `Microsoft-Windows-TaskScheduler/Operational`)
   contra el estado actual (`winfs/scheduler`). Éste es el diferenciador de rigor vs KellerSS.

## Invariantes heredados (Fases 1-3C)

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime
  (stdlib + `golang.org/x/sys`). El parser EVTX es puro Go, sin `wevtapi`.
- Un colector que falla **nunca** tumba el escaneo: el `runner` recupera panics y propaga errores
  como resultado, sin abortar el resto.
- Nunca recolectar contenido de archivos personales, credenciales, historial ni mensajes: solo
  metadatos forenses. Se registran SIDs/usuarios (necesarios para atribución), no payloads
  arbitrarios de eventos fuera de los EventIDs scopeados.
- Código en inglés (identificadores); comentarios y commits en español.
- Los tests corren en CI Linux con fixtures sintéticos; nada depende de un Windows real ni de
  archivos `.evtx` reales de una máquina.

## Decisión de arquitectura: parser híbrido pragmático

Se evaluaron tres estrategias de parseo EVTX:

- **A — Parser EVTX puro completo (renderer BinXML universal).** Máximo rigor y reutilización, pero
  un renderer universal es un proyecto en sí mismo; sobredimensionado para el set de EventIDs que
  importan.
- **B — API de Windows (`wevtapi`, `EvtQuery`/`EvtNext`).** Rápido, rendering robusto gratis, pero
  corre contra el subsistema vivo (no una copia congelada de VSS), no detecta tampering de bajo
  nivel, y **falla si el atacante detuvo o manipuló el servicio EventLog** — justo el escenario que
  provoca un cheater. Rompe CGO-free y la identidad anti-tampering.
- **C — Híbrido pragmático (elegido).** Parser puro para el *framing* de records + señales de
  tampering (CRC de chunk, gaps de record-id, flags), con un decodificador BinXML **scopeado solo a
  los EventIDs que importan** y degradación graceful ante tokens/templates desconocidos. Es el mismo
  patrón "parseo puro + degradación graceful" que ya usa el colector de scheduler. Da lo
  forense-crítico (detección de manipulación de logs) con esfuerzo acotado.

## Layout de paquetes

Siguiendo la convención `winfs/<parser puro>` + `collector/<adapter>`:

```
internal/winfs/evtx/              parser EVTX puro (activo reutilizable)
  evtx.go          framing: header ELF, chunks de 64KB, records, CRC32
  binxml.go        decodificador BinXML pragmático (scopeado)
  templates.go     sustitución de templates + tabla de tokens soportados
  events.go        mapeo tipado de los EventIDs que importan
  tamper.go        señales: gaps de record-id, CRC inválido, flags dirty/full, truncado
  evtx_test.go, binxml_test.go, tamper_test.go

internal/winfs/evtx/evtxtest/     builder de .evtx sintéticos para tests
  builder.go       espejo de reghivetest.Builder

internal/collector/eventlog/      adapter al interface Collector
  eventlog.go      wiring: parsea Security+System, corre correlación
  correlate.go     cross-check puro: 7045↔services, task-events↔scheduler
  eventlog_test.go, correlate_test.go
```

## Componente: parser EVTX (`winfs/evtx`)

### Framing (siempre robusto)

- Header de archivo `ElfFile` (magic `ElfFile\0`, chunk count, flags dirty/full).
- Iteración de chunks de 64KB: header `ElfChnk`, validación **CRC32** (header y datos), rango de
  record-ids (first/last del chunk).
- Records: magic `\x2a\x2a\x00\x00`, tamaño, **record-id monotónico**, timestamp FILETIME (vía
  `wintime`).

### BinXML (pragmático, con degradación)

- Tokens soportados: `OpenStartElement`, `Close`/`CloseEmpty`, `EndElement`, `Value`, `Attribute`,
  `TemplateInstance`, `NormalSubstitution`, `OptionalSubstitution`, `EOF`.
- Tipos de value soportados: string UTF-16 (vía `wintext.DecodeUTF16`), uint8/16/32/64, FILETIME,
  SID, HexInt.
- **Template caching** por offset dentro del chunk (lo exige el formato: instancias posteriores
  referencian un template ya visto por offset).
- Ante token o tipo de value desconocido: no explota — marca el record como `PartialDecode` y sigue.
  Igual que la degradación graceful del scheduler.

### Señales de tampering (`tamper.go`)

- **Gap de record-id**: entre records consecutivos, salto > 1 en el id → registros borrados.
- **CRC de chunk inválido** (header o datos) → manipulación directa del archivo.
- **Flags dirty/full** en el header de archivo → cierre sucio / posible interferencia.
- **Chunk final vacío o record-count menor al declarado** → truncado.

### Superficie pública

```go
// Open parsea un archivo .evtx completo y devuelve records tipados + señales de tampering.
func Open(path string) (*Log, error)

type Log struct {
    Records []Record
    Tamper  []TamperSignal
    Dirty   bool
    Full    bool
}

type Record struct {
    ID           uint64
    Timestamp    time.Time
    EventID      uint16
    Channel      string
    PartialDecode bool
    Fields       map[string]string // solo campos scopeados por EventID
}
```

## Componente: colector de Event Logs (`collector/eventlog`)

### Adapter (`eventlog.go`)

```go
func New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector
```

- `Priority()` = `PriorityDisk` (50), como los demás colectores de disco.
- `Collect()` parsea `securityPath`, `systemPath` y `taskSchedPath` con `winfs/evtx`, deriva las
  vistas tipadas
  (timeline, clears, installs, task-events), reutiliza `winfs/services` y `winfs/scheduler` para el
  estado actual del registro, corre `correlate.CrossCheck`, y emite Artifacts.

### Tipos de Artifact producidos

Cada tipo con su `Type` distinto para que el reporte los distinga:

- `eventlog.session_timeline` — sesiones reconstruidas: boot/shutdown + logon/logoff con logon type
  resuelto, usuario/SID, ventana de sesión.
- `eventlog.log_cleared` — un artifact por cada `1102`/`104`: qué log, cuándo, qué cuenta (si el
  evento sobrevive).
- `eventlog.tamper_signal` — las señales de `tamper.go`.
- `eventlog.desync` — salidas de la correlación.

### Correlación (`correlate.go`, función pura)

```go
func CrossCheck(
    serviceInstalls []InstallEvent,     // 7045 parseados del EVTX
    currentServices []services.Service, // estado actual del registro
    taskEvents      []TaskEvent,        // 106/140/141 del EVTX
    currentTasks    []scheduler.Task,   // estado actual
    logsCleared     bool,               // hubo 1102/104
) []Desync
```

Reglas de desync:

- **Servicio en registro sin `7045`** → `service_no_install_log` (borraron logs o inyección manual
  del registro). Severidad alta.
- **`7045` de un servicio que ya no está en el registro** → `service_installed_then_removed`
  (ejecución + limpieza).
- **Tarea presente sin evento `106`** → `task_no_register_log`.
- **Evento `141` (tarea borrada) pero la tarea sigue en disco/registro** → `task_delete_desync`
  (encaja con la detección XML↔TaskCache de la Fase 3C).

Si `logsCleared` es true, cada desync se anota como **"esperable por borrado de logs"** en vez de
tratarse como falso-positivo — reduce ruido y cuenta la historia correcta (el borrado explica la
ausencia de los logs de instalación).

## Wiring VSS (`live_windows.go`)

```go
securityLog := vss.PathIn(snap, `Windows\System32\winevt\Logs\Security.evtx`)
systemLog   := vss.PathIn(snap, `Windows\System32\winevt\Logs\System.evtx`)
taskSchedLog := vss.PathIn(snap,
    `Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`)
// ...
eventlog.New(securityLog, systemLog, taskSchedLog, systemHive, softwareHive),
```

Mismo fallback a paths en vivo si VSS falla. Los `.evtx` están **siempre en uso** por el servicio
EventLog, así que VSS es la única forma de leerlos consistentes; si el fallback en vivo choca con
lock de archivo, el colector reporta el error sin tumbar el escaneo (`runOne` recupera con
`recover`).

## Manejo de errores (degradación graceful en 3 niveles)

1. Archivo ilegible → Artifact de error, el escaneo sigue.
2. Chunk con CRC inválido → se emite `tamper_signal` y se sigue con los demás chunks.
3. Record con BinXML no decodificable → `PartialDecode`, se conserva lo que sí se pudo extraer.

## Testing (TDD con fixtures sintéticos)

- `evtxtest.Builder` genera `.evtx` sintéticos (header ELF, chunks con CRC correcto, records, un
  template mínimo). Espejo de `reghivetest.Builder`.
- Tests unitarios:
  - Framing/CRC: chunk válido parsea; CRC corrupto emite `tamper_signal`.
  - BinXML: cada EventID scopeado (`4624`, `4634`, `6005`, `6006`, `6008`, `1102`, `104`, `7045`,
    `106`, `140`, `141`) decodifica sus campos; template desconocido → `PartialDecode`.
  - Tamper: gap de record-id, CRC inválido, dirty/full, truncado.
  - `CrossCheck`: cada regla de desync en aislamiento, incluyendo el caso `logsCleared=true` que
    reanota los desync.
- El colector se testea con fixtures sintéticos, sin Windows real; corre en CI Linux.

## Fuera de alcance (fases futuras del roadmap KellerSS)

- 3E: firmas de cheats + análisis de strings/imports.
- 3F: PCA, crash dumps, temp folders.
- 3G: hosts/localhost + sustitución de disco (Disco).
- Renderer BinXML universal (solo se implementa lo scopeado a los EventIDs de esta fase).
- Otros canales de log (Application, Sysmon): esta fase se limita a `Security.evtx`, `System.evtx` y
  `Microsoft-Windows-TaskScheduler/Operational`.
