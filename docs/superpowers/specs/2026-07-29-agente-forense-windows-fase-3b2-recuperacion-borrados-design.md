# Agente Forense Windows — Fase 3B-2 (Acceso Raw al Volumen + Recuperación de Entradas Borradas) — Diseño

**Fecha:** 2026-07-29
**Estado:** Aprobado (pendiente revisión del spec)
**Fase previa:** 3B-1 (fundación MFT + detección de timestomping) — integrada en `master`.

## Contexto y alcance

La Fase 3B ("acceso al MFT") se descompuso en dos sub-fases (ver spec 3B-1). Esta es la
**segunda y última**:

- **3B-1 (hecha):** fundación de lectura de registros MFT + detección de *timestomping* sobre
  archivos **vivos**, vía la API del filesystem (`FSCTL_GET_NTFS_FILE_RECORD`).
- **3B-2 (esta):** acceso **raw** al volumen (boot sector, data runs del `$MFT`, lectura por
  sector alineada), enumeración de **todos** los registros del MFT —incluidos los **borrados**
  (`InUse = 0`)— recuperación de sus metadatos, resolución de ruta completa y detección de
  timestomping también sobre las entradas borradas.

**Objetivo de 3B-2:** recuperar metadatos forenses de archivos **eliminados** del volumen `C:`
(ejecutables, scripts y nombres sospechosos), que la API del filesystem ya no lista porque su
registro está marcado como libre. Cada entrada borrada relevante se reporta como artefacto con
ruta reconstruida y, si aplica, veredicto de timestomping. Se respeta el invariante de
privacidad: solo metadatos, nunca contenido de archivos ni nombres personales.

**Insight que define la arquitectura:** `ENUM_USN_DATA` y `FSCTL_GET_NTFS_FILE_RECORD` (usados
en 3A/3B-1) solo devuelven registros **vivos** — el kernel no expone slots liberados. La única
forma de ver un registro borrado es **leer el disco por debajo del filesystem**: abrir `\\.\C:`,
leer el sector 0 (boot sector `$Boot`), localizar el `$MFT`, decodificar sus *data runs* y
barrer secuencialmente todos los registros. Esta es la razón por la que toda la complejidad de
I/O crudo se difirió deliberadamente a esta sub-fase.

## Decisiones de diseño (brainstorming)

1. **Enfoque de lectura raw: Aproximación A (parseo de boot sector + decodificación de data
   runs).** Leer el boot sector desde el sector 0 para ubicar el clúster inicial del `$MFT`,
   parsear el registro 0 (`$MFT` describe su propia ubicación) para decodificar los data runs de
   su atributo `$DATA`, y hacer lecturas por sector alineadas y secuenciales a lo largo de esos
   *extents* para enumerar **todos** los registros, incluidos los borrados.
   - **Rechazada B (barrido de ordinales vía FSCTL):** `FSCTL_GET_NTFS_FILE_RECORD` iterando por
     número de registro **no devuelve borrados** — mismo límite de API que impide 3A/3B-1 verlos.
   - **Rechazada C (`FSCTL_GET_RETRIEVAL_POINTERS`):** daría los extents del `$MFT` sin parsear
     data runs, pero sigue siendo API del filesystem y no permite enumerar los slots liberados.
     Solo la lectura raw del disco alcanza el objetivo de recuperación.
2. **Reutilizar 3B-1 sin cambios de lógica:** el parseo de registro (`parseRecord`), la
   extracción de SI/FN y la detección de timestomping (`detectTimestomp`) ya son puros y
   agnósticos al origen de los bytes. 3B-2 solo aporta **de dónde** vienen los bytes (disco crudo
   en vez de FSCTL). Se **exportan** esos símbolos desde `mft` para consumirlos (ver más abajo).
3. **Scan acotado a forenses:** igual que 3B-1, se filtra a ejecutables/scripts/nombres
   sospechosos con `fsforensic`. Reduce ruido y respeta privacidad.
4. **Streaming, no carga total:** el `$MFT` puede pesar cientos de MB; se lee en *chunks* (~1 MB)
   a lo largo de los data runs, parseando registro a registro, con un tope `maxRecords` para
   casos patológicos.

## Estructura de paquetes

Se crea el paquete `internal/winfs/ntfs/` (reservado desde 3B-1) para **aislar toda la
complejidad de disco crudo**. El parseo puro y la detección viven ya en `mft` y se reutilizan.

```
internal/winfs/ntfs/
  bootsector.go       # PURO: parsea el boot sector $Boot (bytes/sector, sectores/clúster, clúster $MFT, tamaño de registro)
  bootsector_test.go  #   → testeable cross-platform con boot sectors sintéticos
  dataruns.go         # PURO: decodifica los data runs de un $DATA no-residente en lista de extents (LCN, longitud)
  dataruns_test.go
  ntfs_windows.go     # WINDOWS: abre \\.\C:, lee sectores alineados, barre el $MFT vía extents, recupera borrados
  ntfs_windows_test.go
  ntfs_other.go       # stub no-Windows (ErrUnsupported)
internal/collector/deleted/
  deleted.go          # adaptador al contrato collector.Collector
  deleted_test.go
```

`ntfs` **importa** `mft` (parseo/detección), `fsforensic` (filtro) y `ntfspath` (ruta). No hay
dependencia inversa: `mft` no conoce a `ntfs`.

### Exportación acotada desde `mft` (refactor justificado)

Hoy `parseRecord`, `detectTimestomp`, `Record`, `Timestamps` y `Verdict` son **no exportados**
en `mft` porque 3B-1 los consumía solo internamente. Para que `ntfs` los reutilice sin duplicar
~200 líneas de parseo y la regla de detección, se **exportan** renombrando:

- `parseRecord` → `mft.ParseRecord(buf []byte) (Record, error)`
- `detectTimestomp` → `mft.DetectTimestomp(si, fn Timestamps) Verdict`
- `applyFixup` → `mft.ApplyFixup(buf []byte) ([]byte, error)` — para que `ntfs` obtenga el buffer
  corregido y pueda leer offsets de atributos (lo necesita `nonResidentDataRuns`), sin duplicar
  la lógica del update sequence array.
- `Record`, `Timestamps`, `Verdict` pasan a públicos (ya lo son como tipos; se exporta su uso).
- Se exporta `mft.ErrBadSignature`.

Los llamadores internos de `mft` (en `mft_windows.go`) se adaptan al nuevo nombre; sus tests
existentes deben seguir en verde. Es refactor sobre código que se está tocando, una sola fuente
de verdad, no scope creep. El campo `fnNamespace` (no exportado) permanece privado — es detalle
interno del parseo.

## Modelo de datos y parsing (puro)

### Boot sector

```go
// BootSector describe la geometría NTFS necesaria para ubicar y leer el $MFT.
type BootSector struct {
    BytesPerSector    uint16
    SectorsPerCluster uint8
    MFTCluster        uint64 // LCN del primer clúster del $MFT
    BytesPerRecord    int    // tamaño de un registro FILE (típico 1024)
    ClusterSize       int    // BytesPerSector * SectorsPerCluster (derivado)
}

// ParseBootSector valida la firma NTFS y extrae la geometría desde los 512 bytes del sector 0.
func ParseBootSector(sector []byte) (BootSector, error)
```

**Detalles de parsing (offsets del BPB en el boot sector NTFS):**

- **Firma OEM (`0x03`, 8 bytes):** debe ser `"NTFS    "`. Otro valor → `ErrNotNTFS`.
- **BytesPerSector** (`uint16 @0x0B`), **SectorsPerCluster** (`uint8 @0x0D`).
- **MFTCluster** (`uint64 @0x30`): LCN del primer clúster del `$MFT`.
- **ClustersPerFileRecordSegment** (`int8 @0x40`): si es positivo, es el nº de clústers por
  registro; si es negativo, `BytesPerRecord = 2^(-valor)` (convención NTFS: -10 → 1024 bytes).
- Se valida `BytesPerSector ∈ {512,1024,2048,4096}` y `BytesPerRecord ≥ 512` para descartar boot
  sectors corruptos.

### Data runs

```go
// Extent es una corrida contigua de clústers del $MFT en disco.
type Extent struct {
    StartLCN uint64 // clúster lógico inicial (absoluto)
    Length   uint64 // número de clústers
}

// DecodeDataRuns decodifica la lista de data runs de un atributo $DATA no-residente
// (formato: header nibble con tamaños de length/offset, offset relativo con signo al run previo).
func DecodeDataRuns(runs []byte) ([]Extent, error)

// nonResidentDataRuns localiza el atributo $DATA (0x80) no-residente dentro del buffer de un
// registro FILE ya con fixup aplicado, y devuelve los bytes de sus mapping pairs (data runs).
// Necesario porque mft.ParseRecord solo extrae SI/FN residentes; el $DATA del $MFT lo resuelve
// ntfs por su cuenta. Lee del header no-residente el "mapping pairs offset" (uint16 @0x20 del
// atributo) y recorta desde ahí hasta el fin del atributo.
func nonResidentDataRuns(recordBuf []byte) ([]byte, error)
```

**Detalles de decodificación:**

- Cada run empieza con un byte de cabecera: nibble bajo = nº de bytes de la **longitud**, nibble
  alto = nº de bytes del **offset** (LCN relativo, con signo, respecto al run anterior).
- Cabecera `0x00` = terminador de la lista.
- El offset es **delta con signo** (complemento a dos): un run puede apuntar hacia atrás. El LCN
  absoluto se acumula: `currentLCN += signedDelta`.
- Un offset de longitud cero con longitud presente indica un run **sparse** (hueco); el `$MFT`
  no debería tenerlos, pero se maneja saltándolo sin emitir extent.
- Validaciones: nº de bytes de campo ≤ 8, no exceder el buffer, `Length > 0`.

### Reutilización del parseo de registro

Cada registro FILE leído del disco se pasa a `mft.ParseRecord`, idéntico a 3B-1 (firma `FILE`,
fixup del update sequence array, recorrido de atributos residentes, extracción de SI/FN y
nombre). La diferencia clave: aquí **también** interesan los registros con `InUse = 0`.

## Flujo de lectura raw y recuperación (Windows)

```go
// DeletedEntry es una entrada borrada recuperada del MFT, lista para reportar.
type DeletedEntry struct {
    FullPath string          // ruta reconstruida ("<huérfano>\\..." si el padre no resuelve)
    FileName string
    SI       mft.Timestamps
    FN       mft.Timestamps
    Verdict  mft.Verdict     // timestomping también se evalúa sobre borrados
    RecordNo uint64          // ordinal del registro en el MFT
}

var ErrUnsupported = errors.New("acceso raw NTFS solo disponible en Windows")

func ScanDeleted(ctx context.Context, volume string) ([]DeletedEntry, error)
```

Flujo en `ntfs_windows.go`:

1. Abrir handle read-only a `\\.\C:` (mismo patrón `CreateFile` que USN/MFT:
   `GENERIC_READ`, `FILE_SHARE_READ|WRITE`, `OPEN_EXISTING`).
2. `SetFilePointer` a 0 + `ReadFile` de 512 B → `ParseBootSector` → geometría.
3. Leer el **registro 0** (`$MFT`) desde `MFTCluster * ClusterSize`: `mft.ParseRecord` valida la
   firma y aplica el fixup; luego `nonResidentDataRuns` localiza su atributo `$DATA` **no-residente**
   y `DecodeDataRuns` convierte sus mapping pairs en lista de `Extent`. (El `$DATA` del `$MFT` es
   el único data run que se decodifica en todo el escaneo; ver privacidad.)
4. **Barrido en streaming:** recorrer los extents en orden; por cada uno, leer en chunks de
   ~1 MB (alineados a sector) desde `StartLCN * ClusterSize`, y trocear cada chunk en registros
   de `BytesPerRecord`. Para cada registro:
   a. `mft.ParseRecord`; si falla la firma o el fixup → **saltar** (slot nunca usado o basura).
   b. Filtrar por nombre con `fsforensic.HasForensicExtension` / `IsSuspiciousName`.
   c. Registros **vivos** (`InUse = 1`) se ignoran aquí — ya los cubre el colector de 3B-1;
      este colector emite solo `InUse = 0` (evita duplicar findings).
   d. Construir en paralelo el mapa `parentRef → ntfspath.ParentEntry` a partir de los registros
      vivos que sí son directorios, para reconstruir rutas de los borrados.
5. Para cada borrado que pasa el filtro: `mft.DetectTimestomp(rec.SI, rec.FN)` y ruta vía
   `ntfspath.ResolvePath(parentMap, parentRef, fileName)`. Si el padre ya no resuelve (fue
   borrado o reciclado) se prefija `"<huérfano>\\"`.
6. `context` cancelable en los bucles de extents/chunks (patrón de 3A). Tope `maxRecords` para
   cortar barridos patológicos.

Notas de I/O: `SetFilePointer` a offsets **alineados a sector**; los reads a `\\.\C:` deben ser
múltiplos de `BytesPerSector`. Se usa `SetFilePointerEx`/`ReadFile` de `golang.org/x/sys/windows`.

## Colector y registro

```go
// internal/collector/deleted/deleted.go  (//go:build windows)
type Collector struct { Volume string }
func New() *Collector               // Volume default \\.\C:
func (c *Collector) Name() string   // "deleted_entries"
func (c *Collector) Priority() int  // collector.PriorityDisk
func (c *Collector) Collect(ctx) ([]collector.Artifact, error)
```

`Collect` llama `ScanDeleted`; cada `DeletedEntry` → `Artifact{Type:"deleted_entry",
Source:FullPath, Data:JSON(entry), Collected:now}`. Se registra en
`internal/agent/live_windows.go` junto a los demás colectores de disco (después del de MFT).

## Manejo de errores y privacidad

- **Degradación:** cualquier fallo (sin elevación, volumen no NTFS, boot sector inválido, data
  runs corruptos, disco ilegible) → `error` que el runner convierte en `Finding` INFO. Un
  colector nunca tumba el escaneo. Los fallos de parseo **por registro** se saltan en silencio —
  es normal: la mayoría de los slots del MFT son inválidos o nunca usados.
- **Privacidad (invariante estricto):**
  - Solo se decodifican los data runs del **propio `$MFT`** (registro 0). **Nunca** se decodifican
    ni leen data runs de `$DATA` de archivos arbitrarios → cero acceso a contenido, cero carving.
  - Solo se emiten metadatos forenses (ruta de ejecutables/scripts, timestamps, veredicto). El
    filtro `fsforensic` garantiza que no se reporten nombres de archivos personales.
  - El `parentMap` es transitorio (vive solo durante el escaneo), igual que en 3A.

## Estrategia de testing

- **Tests puros (cross-platform):**
  - `ParseBootSector`: boot sectors sintéticos — firma NTFS válida, firma inválida (`ErrNotNTFS`),
    `BytesPerRecord` positivo (clústers) vs negativo (potencia de 2), geometría fuera de rango.
  - `DecodeDataRuns`: runs sintéticos — un solo run, múltiples runs contiguos, offset **negativo**
    (delta hacia atrás), terminador `0x00`, run sparse, cabecera que excede el buffer (error).
  - Se extiende el helper `buildAttr` de 3B-1 (o uno análogo en `ntfs`) para construir un `$DATA`
    **no-residente** con data runs y verificar el ciclo `ParseRecord` → `DecodeDataRuns`.
- **Test de integración (`//go:build windows`):** `ScanDeleted` sobre `\\.\C:`, valida forma
  (todo `DeletedEntry` tiene `FileName` no vacío y proviene de `InUse = 0`) con `Skip` si no hay
  elevación / volumen no NTFS / disco no accesible.
- **Test de contrato del colector:** `deleted.Collector` cumple `collector.Collector`, `Name`,
  `Priority` y no entra en pánico sin elevación (devuelve error, no crashea).
- **Build:** `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...` y `go vet` limpios. Los
  tests puros corren en cualquier plataforma; los `//go:build windows` se validan compilando.

## Restricciones globales (heredadas)

- Target `GOOS=windows GOARCH=amd64`, **sin CGO**.
- Go 1.25+. Module path `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime.
- Identificadores en inglés; comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Fuera de alcance (posible trabajo futuro)

- Recuperación de **contenido** de archivos borrados (carving de data runs de `$DATA`) — excluido
  por diseño por el invariante de privacidad.
- Barrido de `$MFTMirr`, `$LogFile` o `$UsnJrnl:$J` para correlación temporal más profunda.
- Snapshots VSS para recuperar estado histórico (el paquete `vss` existe pero no se integra aquí).
- Volúmenes distintos de `C:` o discos externos.
