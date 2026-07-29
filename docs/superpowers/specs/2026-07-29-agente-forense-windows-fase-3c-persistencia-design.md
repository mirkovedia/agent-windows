# Agente Forense Windows — Fase 3C: Persistencia (Servicios + Tareas Programadas) (Design)

**Fecha:** 2026-07-29
**Estado:** Aprobado, listo para plan de implementación
**Depende de:** Fases 1-3B2 (interfaz `collector.Collector`, `reghive`, `wintime`, `fsforensic`,
patrón VSS, patrón de build tags `winfs/*`)

## Contexto

El agente forense por consentimiento (telagem/screenshare) reconstruye qué se ejecutó y qué se
borró en la máquina de un jugador de Free Fire. Las Fases 1-3B2 cubrieron evidencia de
*ejecución* (Prefetch, BAM, ShimCache, AmCache) y de *borrado/manipulación* (USN Journal,
timestomping SI vs FN, recuperación cruda de entradas MFT borradas).

Comparando contra herramientas equivalentes de la comunidad (KellerSS-PC), se identificó un hueco
de **superficie de persistencia**: cómo sobrevive un cheat a un reinicio. Dos fuentes cubren esto:

- **Servicios** (`SYSTEM\CurrentControlSet\Services`): un cheat kernel-mode (el más peligroso,
  bypasea detección en user-mode) necesita registrarse como servicio con un driver.
- **Tareas programadas** (`C:\Windows\System32\Tasks\`): un mecanismo común de persistencia y
  relanzamiento en user-mode, frecuentemente usado con la tarea marcada como oculta.

Cada tarea programada además deja **dos rastros independientes**: el XML en disco y una entrada
espejo en el hive `SOFTWARE` (`TaskCache\Tree`). Si alguien borra el XML a mano para ocultar una
tarea pero no logra limpiar el registro (requiere privilegio SYSTEM), ambas fuentes quedan
desincronizadas — la misma lógica de "dos fuentes que deberían coincidir y no coinciden" que ya
usa la Fase 3B-1 para detectar timestomping vía SI vs FN.

## Objetivo

Detectar y reportar:

1. **Drivers no estándar** instalados como servicio (`Type` = kernel o filesystem driver) cuyo
   `ImagePath` no vive donde Windows instala drivers legítimamente — superficie de cheats
   kernel-mode.
2. **Tareas programadas** ocultas, o cuyo comando/argumentos apuntan a un ejecutable/script con
   extensión forense o nombre sospechoso.
3. **Desincronización** entre el XML de una tarea en disco y su entrada en `TaskCache\Tree` —
   evidencia de manipulación activa para ocultar rastros.

## Invariantes heredados (Fases 1-3B2)

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime
  (stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` categoría INFO (el
  `runner` recupera panics y propaga errores).
- Nunca recolectar contenido de archivos personales, credenciales, historial ni mensajes: solo
  metadatos forenses.
- Código en inglés (identificadores); comentarios y commits en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Arquitectura

```
internal/winfs/wintext/          NUEVO: helper compartido puro
  wintext.go        DecodeUTF16(b []byte) string  (semántica: corta en \x00\x00)
  (refactor: shimcache, amcache, prefetch pasan a usarlo — mismo patrón que
   wintime en 3A. mft y usn NO se tocan: su variante es de longitud exacta,
   semántica distinta, y forzarlas al mismo helper cambiaría su comportamiento)

internal/winfs/services/         NUEVO: parseo puro del subárbol Services
  services.go        parsea *reghive.Key -> []DriverService; heurística
                      "¿ImagePath fuera de System32\drivers?" para drivers

internal/winfs/scheduler/        NUEVO: parseo puro de tareas + cross-check
  taskxml.go         decodifica XML de tarea (BOM UTF-16 -> UTF-8 -> encoding/xml)
  taskcache.go       camina TaskCache\Tree (reghive) -> rutas relativas + Id
  diff.go            compara set(archivos) vs set(TaskCache) -> desincronía

internal/collector/services/     NUEVO: adaptador (Priority = PriorityRegistry)
internal/collector/scheduler/    NUEVO: adaptador (Priority = PriorityDisk)
```

Ningún paquete nuevo necesita build tag `windows`: todo es `reghive` puro (ya cross-platform) +
`os.ReadFile`/`os.ReadDir`/`filepath.WalkDir` de la stdlib — corren y se testean en cualquier
host, igual que `bam`/`prefetch` hoy. Solo `live_windows.go` (ya con su tag) los registra.

`services` reutiliza el `systemHive` que hoy recibe `bam.New()`/`shimcache.New()` — cero
infraestructura VSS nueva. `scheduler` necesita el hive `SOFTWARE` (para `TaskCache`), que
`live_windows.go` no snapshotea todavía: se agrega una tercera línea `softwareHive :=
vss.PathIn(snap, ...)`, mismo patrón que las dos existentes. La carpeta `System32\Tasks\` se lee
en vivo sin VSS (sus XML no están bloqueados, igual que Prefetch).

## Componentes e interfaces

### `internal/winfs/wintext` (helper compartido)

```go
// DecodeUTF16 decodifica una cadena UTF-16LE terminada en \x00\x00 (o hasta
// agotar el buffer). Usado para valores REG_SZ/REG_EXPAND_SZ y para contenido
// XML tras remover el BOM.
func DecodeUTF16(b []byte) string
```

Migra `shimcache/parse.go`, `amcache/amcache.go` y `prefetch/parse.go` a llamar esta función en
vez de su copia local (misma semántica exacta que ya tenían: corte en el primer `\x00\x00`).

### `internal/winfs/services` (puro)

```go
type DriverService struct {
    Name      string
    ImagePath string // ya decodificado, sin normalizar
    Type      uint32 // REG_DWORD: 1=kernel driver, 2=filesystem driver, ...
    Start     uint32 // REG_DWORD: 0=Boot..4=Disabled
}

// ParseServices recorre las subclaves de la clave "Services"
// (SYSTEM\CurrentControlSet\Services) y decodifica Name/ImagePath/Type/Start
// de cada una. Una subclave con Type/ImagePath faltante o malformado se
// omite; no aborta el resto.
func ParseServices(servicesKey *reghive.Key) ([]DriverService, error)

// IsNonMicrosoftDriver reporta si el servicio es driver (Type 1 o 2) cuyo
// ImagePath normalizado no cae bajo %SystemRoot%\System32\drivers\. Es una
// heurística por RUTA, no por firma de editor: sin CGO ni dependencias
// externas no hay validación de Authenticode offline. Cubre tanto binarios
// de terceros como maliciosos que no siguen la convención de instalación de
// Windows — la señal más fuerte disponible sin verificación de firma.
func IsNonMicrosoftDriver(s DriverService) bool
```

Valores `Type` relevantes (de `winnt.h`): `SERVICE_KERNEL_DRIVER = 0x1`,
`SERVICE_FILE_SYSTEM_DRIVER = 0x2`. Cualquier otro valor (Win32 own/share process, etc.) nunca
pasa el filtro, sin importar su `ImagePath`.

Normalización de `ImagePath` (dentro de `IsNonMicrosoftDriver`): minúsculas; strip de prefijo
`\??\`; `\systemroot\` (case-insensitive) al inicio se reescribe a `c:\windows\`; luego se
verifica si el resultado contiene `\windows\system32\drivers\`.

### `internal/winfs/scheduler` (puro)

```go
// TaskDefinition es una tarea programada parseada desde su XML.
type TaskDefinition struct {
    RelPath   string // ruta relativa bajo Tasks\, ej. "Microsoft\Windows\Foo\Bar"
    Command   string // <Actions><Exec><Command>
    Arguments string // <Actions><Exec><Arguments>
    Hidden    bool   // <Settings><Hidden>
    Author    string // <RegistrationInfo><Author>
}

// ParseTaskXML decodifica un archivo de definición de tarea. Detecta BOM
// UTF-16LE (0xFF 0xFE) al inicio del buffer: si está presente, decodifica
// con wintext.DecodeUTF16 y convierte a UTF-8 antes de pasarlo a
// encoding/xml; si no, asume UTF-8 y lo pasa directo. Necesario porque
// encoding/xml no soporta UTF-16 nativamente y el proyecto no puede sumar
// golang.org/x/text (dependencia externa fuera de las invariantes del
// proyecto).
func ParseTaskXML(raw []byte, relPath string) (TaskDefinition, error)

// CachedTask es una entrada hoja del árbol TaskCache\Tree con su Id (GUID).
type CachedTask struct {
    RelPath string // misma convención de ruta relativa que TaskDefinition
    ID      string // valor "Id" (GUID) de la subclave hoja
}

// WalkTaskCacheTree recorre recursivamente la clave Tree y devuelve toda
// hoja que tenga un valor "Id" (las claves intermedias sin ese valor son
// carpetas, no tareas).
func WalkTaskCacheTree(treeKey *reghive.Key) ([]CachedTask, error)

// DesyncKind distingue las dos direcciones de desincronización.
type DesyncKind string

const (
    // HiveOnly: TaskCache referencia una tarea sin XML en disco. Señal
    // fuerte — alguien borró el archivo visible pero no pudo (o no supo)
    // limpiar el registro.
    HiveOnly DesyncKind = "hive_only"
    // FileOnly: el XML existe pero no está en TaskCache. Señal débil/
    // ambigua (puede ser una condición de carrera de creación reciente).
    FileOnly DesyncKind = "file_only"
)

// Desync es una discrepancia entre las tareas en disco y las registradas en TaskCache.
type Desync struct {
    RelPath     string
    Kind        DesyncKind
    TaskCacheID string // solo poblado si Kind == HiveOnly
}

// DiffTasks compara el set COMPLETO de tareas en disco (sin filtrar por
// sospecha) contra el de TaskCache y devuelve las discrepancias. Debe
// recibir el listado completo: una tarea borrada del disco por definición
// no puede pasar un filtro de "sospechoso" (ya no existe para evaluarla), así
// que filtrar antes de diffear perdería justamente la detección hive_only.
func DiffTasks(onDisk []TaskDefinition, cached []CachedTask) []Desync
```

### Colectores

```go
// internal/collector/services — Priority = PriorityRegistry
type Collector struct { HivePath string }
func New(systemHivePath string) *Collector
func (c *Collector) Name() string  { return "services" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }
func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error)

// internal/collector/scheduler — Priority = PriorityDisk
type Collector struct {
    TasksDir         string
    SoftwareHivePath string
}
func New(tasksDir, softwareHivePath string) *Collector
func (c *Collector) Name() string  { return "scheduled_tasks" }
func (c *Collector) Priority() int { return collector.PriorityDisk }
func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error)
```

`services.Collect`: abre el hive → `OpenKey("ControlSet001\Services")` (fallback
`ControlSet002`, mismo patrón que BAM) → `services.ParseServices` → filtra
`IsNonMicrosoftDriver` → `Artifact{Type:"service_driver", Source: ImagePath, Data: json}` por
cada servicio filtrado.

`scheduler.Collect`: enumera `TasksDir` en vivo (`filepath.WalkDir`) → `ParseTaskXML` por
archivo → `[]TaskDefinition` completo. Intenta abrir el hive `SOFTWARE` → `OpenKey(".../TaskCache
\Tree")` → `WalkTaskCacheTree` → `[]CachedTask`; si el hive o la clave no están disponibles, se
omite el cross-check pero se sigue con el resto (ver "Manejo de errores"). `DiffTasks` sobre el
listado completo → `Artifact{Type:"scheduled_task_desync", ...}` por cada `Desync` (campos
mínimos: `RelPath`, `Kind`, `TaskCacheID` — nunca `Command`/`Arguments`, ver "Filtrado y
privacidad"). Filtra el listado en disco por sospechoso(`Command`/`Arguments`) || `Hidden` →
`Artifact{Type:"scheduled_task", ...}` por cada tarea filtrada. **Corrección post-diseño:** no
se usa la whitelist de extensión forense aquí (a diferencia de USN, donde se combina con la razón
del evento) — el `Command` de una tarea casi siempre apunta a un `.exe`, así que esa extensión no
discrimina nada y reportaría casi cualquier tarea del sistema. Detectado por el test de la Tarea 7
del plan de implementación.

Se registran ambos en `internal/agent/live_windows.go` junto a los colectores existentes.

## Flujo de datos

```
services.Collect(ctx):
  reghive.Open(SYSTEM) -> OpenKey("ControlSet001\Services", fallback 002)
    -> ParseServices()          recorre subclaves, decodifica Type/Start/ImagePath
    -> filtra IsNonMicrosoftDriver()
    -> Artifact{Type:"service_driver", Source: ImagePath, ...}

scheduler.Collect(ctx):
  filepath.WalkDir(TasksDir)    enumera XML en vivo (sin VSS, como Prefetch)
    -> ParseTaskXML() por archivo -> []TaskDefinition (COMPLETO, sin filtrar)
  reghive.Open(SOFTWARE) -> OpenKey(".../TaskCache\Tree")     (si falla: se salta este bloque)
    -> WalkTaskCacheTree()       -> []CachedTask
  DiffTasks(onDisk completo, cached)   -> []Desync
    -> Artifact{Type:"scheduled_task_desync", RelPath, Kind, TaskCacheID}
  filtra onDisk: sospechoso(Command/Arguments) || Hidden
    -> Artifact{Type:"scheduled_task", RelPath, Command, Arguments, Hidden, Author}
```

## Manejo de errores

- **Hive `SYSTEM` inaccesible/corrupto** (`services`): error se propaga → `runner` → INFO. Vacía
  todo el colector (no hay servicios sin el hive).
- **`ControlSet001\Services` no existe**: fallback a `ControlSet002`, igual que BAM.
- **Subclave de servicio con `Type`/`Start`/`ImagePath` faltante o malformado**: se omite esa
  subclave, no aborta la enumeración (patrón `continue` de `parseBAM`).
- **Hive `SOFTWARE` inaccesible, o `TaskCache\Tree` no existe** (`scheduler`): a diferencia de
  `services`, esto NO aborta el colector completo — se omite solo el bloque de cross-check (sin
  artifacts `scheduled_task_desync`), pero se sigue reportando lo encontrado en los XML del
  disco. Perder toda la señal de tareas por un fallo transitorio de VSS en una sola de las dos
  fuentes sería peor que degradar con gracia; mismo espíritu que ya tiene `RunLive` cuando el
  snapshot VSS entero falla.
- **`TasksDir` raíz inaccesible**: error real, se propaga → INFO. Un XML individual corrupto o
  un archivo no-XML dentro del árbol: se omite ese archivo, sigue el `WalkDir`.
- **`ctx` cancelado**: se chequea por archivo en el `WalkDir` (patrón Prefetch/USN) y por
  servicio en la enumeración; devuelve lo recolectado hasta el corte.

## Filtrado y privacidad

`ImagePath` de un driver no es dato personal — es una ruta de ejecución a nivel sistema, igual de
legítima que un `.exe` reportado por USN. `Command`/`Arguments`/`Hidden` de una tarea solo salen
si ya pasaron el filtro forense-o-sospechoso-u-oculta acordado, mismo límite de privacidad que
USN (Fase 3A). El campo `Author` de una tarea a veces trae un username
(`DESKTOP-X\Usuario`) — no es una fuga nueva: MFT/USN/Prefetch ya exponen rutas
`C:\Users\<nombre>\...` cuando el ejecutable vive ahí; es metadato forense estándar, no
contenido personal.

Los artifacts `scheduled_task_desync` se mantienen **deliberadamente mínimos**
(`RelPath`+`Kind`+`TaskCacheID`, nunca `Command`/`Arguments`): una desincronización se reporta
pase o no el filtro de sospecha del punto anterior, así que el contenido de la tarea no debe
filtrarse por esa vía — la discrepancia en sí es la señal, no lo que la tarea ejecuta.

## Testing (TDD)

Todo el paquete es testeable con fixtures sintéticas. A diferencia de USN/MFT/NTFS, **no
necesita ningún test de integración con privilegios reales para la lógica pura** (no hay
syscalls nuevos: todo es `reghive` puro + stdlib):

| Archivo | Tests |
|---------|-------|
| `wintext_test.go` | Buffer con terminador nulo → corta correctamente; buffer sin nulo → decodifica todo; buffer vacío → `""`. |
| `services_test.go` (paquete `services`) | `ParseServices` sobre hive sintético (mismo generador de fixtures que `reghive`/BAM) → `Type`/`Start`/`ImagePath` correctos; subclave con valor faltante → se omite sin abortar. `IsNonMicrosoftDriver`: driver en `System32\drivers` → `false`; driver en `Temp`/`AppData` → `true`; servicio Win32 (no driver) → `false` aunque el path sea raro; variantes de `\??\` y `\SystemRoot\`. |
| `taskxml_test.go` | XML UTF-16 con BOM → parsea `Command`/`Arguments`/`Hidden`/`Author`; XML UTF-8 sin BOM → también; XML corrupto/truncado → error. |
| `taskcache_test.go` | Árbol `Tree` sintético con carpetas anidadas y hojas con/sin valor `Id` → `WalkTaskCacheTree` devuelve solo las hojas con `Id`, con `RelPath` reconstruido correctamente. |
| `diff_test.go` | Mismo set en ambos lados → sin desyncs; entrada solo en `cached` → `HiveOnly` con `TaskCacheID` poblado; entrada solo en `onDisk` → `FileOnly`. |
| `services_test.go` (colector) | Metadata (`Name`/`Priority`); `Collect` sobre hive fixture → artifacts `service_driver`; variante con el path real por defecto (`C:\Windows\System32\config\SYSTEM`) + `t.Skip` si falla (mismo patrón que `deleted_test.go` de 3B-2). |
| `scheduler_test.go` (colector) | Metadata; `Collect` sobre directorio + hive sintéticos → los 3 tipos de artifact esperados; variante con paths reales por defecto + `t.Skip` si falla. |

Ningún archivo necesita build tag `windows`: los tests con paths reales (`C:\Windows\...`)
simplemente fallan y hacen `t.Skip` en cualquier host sin ese path exacto, Windows o no — se
degradan solos sin necesidad de gate explícito por plataforma.

## Fuera de alcance

- Validación de firma Authenticode de drivers (la heurística es solo por ruta).
- Otras categorías identificadas en la comparación con KellerSS-PC pero aún no diseñadas:
  `AuthModule` (verificación de logins — definición ambigua, no confirmada), sustitución de
  disco, crash dumps/WER, análisis de carpetas Temp, Program Compatibility Assistant (PCA),
  Event Log, hosts file, y matching contra firmas de cheats conocidos. Cada una necesita su
  propio ciclo de brainstorming antes de diseñarse.
- Motor de correlación/severidad (Fase 4/5, ya reservado en la nota de cierre de la Fase 3A): los
  findings de esta fase también salen como INFO neutro, igual que las fases anteriores.
