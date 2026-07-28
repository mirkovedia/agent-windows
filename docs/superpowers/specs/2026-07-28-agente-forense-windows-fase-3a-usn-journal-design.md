# Agente Forense Windows — Fase 3A: Colector USN Journal (Design)

**Fecha:** 2026-07-28
**Estado:** Aprobado, listo para plan de implementación
**Depende de:** Fases 1-2 (interfaz `collector.Collector`, `report`, `runner`, patrón de build tags `winfs/*`)

## Contexto

El agente forense por consentimiento (telagem/screenshare) reconstruye qué se
ejecutó y qué se borró en la máquina de un jugador de Free Fire, con su presencia
y aceptación explícita. Las Fases 1-2 entregaron el esqueleto (elevación,
colectores de ejecución Prefetch/BAM/ShimCache/AmCache, reporte firmado Ed25519
con cadena de custodia, contrato de subida) sobre primitivas Windows de bajo nivel
(VSS, parser regf, descompresión MAM).

La Fase 3 agrega detección de **borrado de archivos** (señal anti-forense) y
reconstrucción de actividad del sistema de archivos. Por diferencia de dificultad,
se descompone en dos sub-fases con specs y planes independientes:

- **Fase 3A (este spec):** colector USN Journal vía FSCTL. No requiere parseo de
  MFT crudo. Fundacional y de menor riesgo.
- **Fase 3B (spec futuro):** primitiva `winfs/ntfs` — acceso raw a `\\.\C:`,
  parseo de boot sector + MFT, detección de *timestomping*
  (`$STANDARD_INFORMATION` vs `$FILE_NAME`) y recuperación de entradas borradas
  que el journal ya rotó.

## Objetivo

Detectar y reportar eventos forensicamente relevantes del USN Change Journal del
volumen `C:` — borrados, renombrados, creación y sobrescritura de **ejecutables y
scripts** — con **ruta completa** para trazabilidad y transparencia, respetando
el invariante de privacidad del agente (solo metadatos forenses, nunca contenido
ni nombres de archivos personales).

## Invariantes heredados (Fases 1-2)

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias
  externas en runtime (stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding`
  categoría INFO (el `runner` recupera panics y propaga errores).
- Nunca recolectar contenido de archivos personales, credenciales, historial ni
  mensajes: solo metadatos forenses.
- Código en inglés (identificadores); comentarios y commits en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Arquitectura

La 3A introduce dos paquetes nuevos y una extracción de helper compartido. El
USN Journal se lee vía `DeviceIoControl` (FSCTL) sobre un handle read-only del
volumen `\\.\C:`; **no** toca el MFT crudo (eso es 3B).

```
internal/winfs/wintime/          NUEVO: helper compartido
  wintime.go                       FiletimeToTime(uint64) time.Time
  wintime_test.go
  (refactor: prefetch, shimcache, bam, amcache usan este helper en vez
   de duplicar filetimeToTime)

internal/winfs/usn/              NUEVO: primitiva USN (FSCTL)
  record.go        parseo puro de USN_RECORD_V2/V3 (cross-platform, testeable)
  path.go          resolución de ruta desde parentMap (puro)
  filter.go        whitelist extensión + patrones + máscara de razones (puro)
  usn_windows.go   CreateFile(\\.\C:), QUERY/ENUM/READ_USN_JOURNAL (Windows)
  usn_other.go     stubs !windows -> ErrUnsupported
  record_test.go / path_test.go / filter_test.go / usn_windows_test.go

internal/collector/usn/          NUEVO: colector
  usn.go           implementa collector.Collector (Priority = PriorityDisk)
  usn_test.go
```

**Separación de responsabilidades:** el parseo binario de records, la resolución
de rutas y el filtrado son **funciones puras** (aquí vive el TDD, corren en
cualquier host). Solo `usn_windows.go` toca syscalls. Es el mismo patrón de
`reghive`/`compression`/`vss` de las Fases 1-2.

## Componentes e interfaces

### `internal/winfs/wintime`

Extrae la conversión FILETIME→`time.Time` hoy duplicada en `prefetch/parse.go`,
`shimcache/parse.go` y en línea en `bam/bam.go` y `amcache/amcache.go`.

- `func FiletimeToTime(ft uint64) time.Time` — 100ns desde 1601-01-01 UTC a
  `time.Time` UTC. `ft == 0` devuelve `time.Time{}` (cero).

Refactor: los cuatro colectores existentes pasan a llamar
`wintime.FiletimeToTime`. Es una mejora dirigida justificada porque la Fase 3
reutiliza la conversión (según las notas del plan de Fases 1-2) y elimina
duplicación antes de introducir un quinto consumidor.

### `internal/winfs/usn` — primitiva

Tipos y funciones puras:

```go
// Record es un evento del USN Change Journal, ya parseado.
type Record struct {
    USN        int64     // número de secuencia del journal
    FileRef    uint64    // FileReferenceNumber (índice MFT + secuencia)
    ParentRef  uint64    // ParentFileReferenceNumber
    Reason     uint32    // máscara USN_REASON_*
    Timestamp  time.Time // FILETIME del evento (UTC)
    FileName   string    // nombre hoja (UTF-16 decodificado)
}

// parseRecord parsea un USN_RECORD_V2 o V3 desde un buffer. Devuelve el record
// y cuántos bytes consumió (RecordLength) para avanzar al siguiente.
// V2 usa referencias de 64 bits; V3 usa FILE_ID_128 — se truncan a los 64 bits
// bajos, que en NTFS coinciden con el número de entrada MFT + secuencia. Se
// prioriza V2 (el default de READ_USN_JOURNAL); V3 se detecta por MajorVersion==3.
func parseRecord(buf []byte) (Record, int, error)

// ParentEntry es una fila del mapa de rutas construido con ENUM_USN_DATA.
type ParentEntry struct {
    Name      string
    ParentRef uint64
}

// resolvePath reconstruye la ruta completa subiendo por parentMap desde el
// FileRef dado. Si un padre no está en el mapa (p.ej. archivo borrado), corta
// con el fallback unresolvedPrefix. rootRef (0x5) es la raíz del volumen.
func resolvePath(parentMap map[uint64]ParentEntry, ref uint64, leaf string) string

// Filtros puros:
func hasForensicExtension(name string) bool       // .exe/.dll/.sys/.bat/.ps1/.cmd/.vbs/.scr/.msi
func isSuspiciousName(name string) bool            // cheat/inject/loader/aimbot/wipe/...
func reasonIsRelevant(reason uint32) bool          // DELETE/RENAME_*/CREATE/DATA_TRUNCATION/DATA_OVERWRITE
```

Constantes de razones (de `winioctl.h`):

```
USN_REASON_DATA_OVERWRITE   = 0x00000001
USN_REASON_DATA_TRUNCATION  = 0x00000004
USN_REASON_FILE_CREATE      = 0x00000100
USN_REASON_FILE_DELETE      = 0x00000200
USN_REASON_RENAME_OLD_NAME  = 0x00001000
USN_REASON_RENAME_NEW_NAME  = 0x00002000
```

Windows (`usn_windows.go`):

```go
// ErrUnsupported se devuelve fuera de Windows.
var ErrUnsupported = errors.New("USN journal solo disponible en Windows")

// ReadJournal abre el volumen, construye el mapa de rutas y devuelve los
// records relevantes ya filtrados y con ruta resuelta.
func ReadJournal(ctx context.Context, volume string) ([]Entry, error)

// Entry es un Record enriquecido con la ruta completa resuelta y flags.
type Entry struct {
    Record
    FullPath   string
    Suspicious bool
}
```

`ReadJournal` internamente:
1. `CreateFile(\\.\C:, GENERIC_READ, FILE_SHARE_READ|WRITE, OPEN_EXISTING)`.
2. `DeviceIoControl(FSCTL_QUERY_USN_JOURNAL)` → `USN_JOURNAL_DATA` (journalID,
   NextUsn, MaxSize). Si devuelve `ERROR_JOURNAL_NOT_ACTIVE`/`DELETE_IN_PROGRESS`,
   retorna error (el colector lo convierte en INFO).
3. Pase 1 — `FSCTL_ENUM_USN_DATA` en bucle, acumulando
   `map[FileRef]ParentEntry` de los archivos vigentes.
4. Pase 2 — `FSCTL_READ_USN_JOURNAL` desde `StartUsn=0`, iterando por chunks
   hasta agotar el journal; parsea cada record con `parseRecord`, aplica
   `reasonIsRelevant` + (`hasForensicExtension` || `isSuspiciousName`),
   resuelve ruta, marca `Suspicious`, respeta `ctx.Done()`.

`usn_other.go`: `func ReadJournal(...) ([]Entry, error) { return nil, ErrUnsupported }`.

### `internal/collector/usn` — colector

```go
type Collector struct { Volume string } // default `\\.\C:` (path del dispositivo de volumen)

func New() *Collector
func (c *Collector) Name() string  { return "usn" }
func (c *Collector) Priority() int { return collector.PriorityDisk }
func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error)
```

`Collect` llama a `usn.ReadJournal`, serializa cada `Entry` a `collector.Artifact`
(`Type: "usn"`, `Source: FullPath`, `Data`: JSON del entry). Un error de
`ReadJournal` se propaga y el `runner` lo vuelve INFO.

Se registra en `internal/agent/live_windows.go` junto a los colectores existentes.
Lee del volumen **vivo** (`\\.\C:`), no del snapshot VSS: es un FSCTL read-only
que no requiere shadow copy.

## Flujo de datos

```
CreateFile("\\.\C:")                     handle read-only del volumen
  -> FSCTL_QUERY_USN_JOURNAL             journalID, NextUsn, MaxSize
       (si journal inactivo -> error -> INFO finding)
  -> FSCTL_ENUM_USN_DATA (pase 1)        parentMap: FileRef -> {nombre, parentRef}
  -> FSCTL_READ_USN_JOURNAL (pase 2)     itera desde USN 0 hasta el final
       por cada record:
         parseRecord()                   -> Record{refs, reason, timestamp, fileName}
         reasonIsRelevant(reason)?       descarta CLOSE-solo, atributos, etc.
         hasForensicExtension || isSuspiciousName ?   descarta docs personales
         resolvePath(parentMap)          C:\...\ruta\completa (o <sin-resolver>\nombre)
         -> collector.Artifact{Type:"usn", Source: fullPath, Data: json}
```

## Filtrado y privacidad

Tres capas en `filter.go`, todas puras:

1. **Máscara de razones:** solo DELETE, RENAME_OLD/NEW, CREATE, DATA_TRUNCATION,
   DATA_OVERWRITE. El journal emite muchos eventos por archivo (p.ej. `CLOSE`);
   se retiene solo lo relevante.
2. **Whitelist de extensión:** `.exe .dll .sys .bat .ps1 .cmd .vbs .scr .msi`.
   Cualquier otra extensión se descarta **antes** de resolver la ruta, así los
   nombres de documentos personales ni se procesan.
3. **Patrones sospechosos:** subcadenas case-insensitive (`cheat`, `inject`,
   `loader`, `bypass`, `aimbot`, `macro`, `esp`, `hook`, `wipe`, `ccleaner`,
   `bleachbit`). Un match marca `Suspicious=true` (severidad real llega en Fase 4;
   hoy `resultToFindings` emite INFO).

**Privacidad neta:** solo salen del equipo rutas de ejecutables/scripts — nunca
nombres de documentos, fotos ni mensajes. La ruta completa de un `.exe` es
transparencia forense legítima, no dato personal. Coherente con el
`CollectionSummary` ya consentido ("Rastros de borrado de archivos").

## Manejo de errores

- **Journal deshabilitado/inexistente** (`ERROR_JOURNAL_NOT_ACTIVE`): `Collect`
  retorna error -> `runner` -> INFO ("USN journal no activo"). Es en sí un dato
  forense: alguien pudo borrarlo con `fsutil usn deletejournal`.
- **Access denied al abrir `\\.\C:`**: error no fatal -> INFO. (El entrypoint ya
  exige elevación.)
- **Buffer corrupto / versión de record desconocida:** se saltea ese record y se
  continúa; no aborta.
- **`ctx` cancelado (timeout global):** corta la iteración y devuelve lo
  recolectado (mismo patrón que Prefetch).
- **No-Windows:** `usn_other.go` -> `ErrUnsupported`.

## Testing (TDD)

Todo lo puro es cross-platform y se testea nativo:

| Archivo | Tests |
|---------|-------|
| `wintime_test.go` | `FiletimeToTime` contra FILETIME conocido -> instante UTC esperado; epoch cero -> `time.Time{}`. |
| `record_test.go` | Construye buffers sintéticos `USN_RECORD_V2` (y V3) y valida parseo de `FileName` (UTF-16), `Reason`, `Timestamp`, refs, `RecordLength` retornado. Rechaza record truncado / versión desconocida. |
| `path_test.go` | `parentMap` sintético -> ruta completa; caso raíz (FileRef `0x5`); **padre ausente** -> fallback `<sin-resolver>\nombre`; profundidad máxima (evita ciclos). |
| `filter_test.go` | Extensión dentro/fuera de whitelist; `reasonIsRelevant` (delete sí, close-solo no); `isSuspiciousName` marca match. |
| `usn_windows_test.go` | Integración real: si no hay elevación o journal inactivo, `t.Skip`. Si corre, valida artefactos con rutas resueltas. |

**Fixtures:** los buffers USN se generan en código (structs -> bytes LE), sin
binarios versionados (igual que el generador MAM de la Fase 1).

## Fuera de alcance (Fase 3B y posteriores)

- Parseo de MFT crudo, boot sector, `winfs/ntfs`.
- Detección de *timestomping* (`$STANDARD_INFORMATION` vs `$FILE_NAME`).
- Recuperación de entradas borradas que el journal ya rotó.
- Filtrado por directorio para archivos borrados cuyo padre ya no existe
  (parcialmente cubierto por el fallback `<sin-resolver>`; la resolución completa
  post-borrado depende del MFT de 3B).
- Motor de correlación / severidad real (Fase 4): hoy los findings son INFO
  neutros a propósito.
```
