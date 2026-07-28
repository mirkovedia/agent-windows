# Agente Forense Windows — Fase 3B-1 (Fundación MFT + Detección de Timestomping) — Diseño

**Fecha:** 2026-07-28
**Estado:** Aprobado (pendiente revisión del spec)
**Fase previa:** 3A (colector USN Journal) — integrada en `master`.

## Contexto y alcance

La Fase 3B ("acceso al MFT") es grande y se **descompone en dos sub-fases**, cada una con su
propio spec → plan → implementación:

- **3B-1 (esta):** fundación de lectura de registros MFT + detección de *timestomping*.
- **3B-2 (futura):** acceso raw al volumen (boot sector, data runs del `$MFT`, lectura por
  sector), decodificación de `$DATA`, enumeración/recuperación de entradas borradas
  (`InUse = 0`) y resolución de ruta completa post-borrado.

**Objetivo de 3B-1:** detectar manipulación de timestamps (*timestomping*) en ejecutables,
scripts y archivos de nombre sospechoso del volumen `C:`, comparando los timestamps de
`$STANDARD_INFORMATION` (SI) contra los de `$FILE_NAME` (FN) de cada registro MFT. Cada
detección se reporta como un artefacto forense con ruta completa, respetando el invariante de
privacidad (solo metadatos, nunca contenido ni nombres de archivos personales).

**Insight que define la arquitectura:** `$SI` (0x10) y `$FILE_NAME` (0x30) son **siempre
atributos residentes** dentro del registro MFT. Por lo tanto, la detección de timestomping
**nunca necesita decodificar data runs** — los data runs solo hacen falta para leer `$DATA`
(contenido de archivo, o el propio `$MFT`). Esto empuja toda la complejidad de lectura raw
hacia 3B-2.

## Decisiones de diseño (brainstorming)

1. **Descomponer 3B** en 3B-1 (fundación + timestomping) y 3B-2 (recuperación de borrados).
2. **Criterio de scan:** solo archivos forenses (ejecutables/scripts/nombres sospechosos),
   reutilizando el filtro de 3A. Rápido, bajo ruido, alineado al objetivo anti-cheat.
3. **Enfoque de lectura MFT: Híbrido (C).** Reutilizar `ENUM_USN_DATA` (de 3A) para enumerar
   el MFT una vez y filtrar a forenses; para cada candidato pedir su registro con
   `FSCTL_GET_NTFS_FILE_RECORD`. Sin lecturas raw ni data runs en esta sub-fase. El acceso raw
   crudo queda contenido en 3B-2, donde de verdad se necesita.

## Estructura de paquetes

Sigue el patrón de 3A: parsing puro separado de las syscalls.

```
internal/winfs/mft/
  record.go         # PURO: parsea un registro FILE del MFT (fixup + atributos), extrae SI y FN
  record_test.go    #   → testeable cross-platform con registros sintéticos
  timestomp.go      # PURO: dado SI y FN, decide si hay timestomping
  timestomp_test.go
  mft_windows.go    # WINDOWS: FSCTL_GET_NTFS_FILE_RECORD + enumeración ENUM_USN_DATA + orquestación
  mft_windows_test.go
  mft_other.go      # stub no-Windows (ErrUnsupported)
internal/collector/mft/
  mft.go            # adaptador al contrato collector.Collector
  mft_test.go
```

Se usa el nombre de paquete `mft` (no `ntfs`): en el enfoque híbrido no hay acceso raw
todavía. `internal/winfs/ntfs` queda reservado para 3B-2. Se reutiliza
`wintime.FiletimeToTime`.

### Refactor acotado de extracción compartida

El filtro forense (`hasForensicExtension`, `isSuspiciousName`) y la resolución de ruta
(`resolvePath`, `ParentEntry`) hoy viven **unexported** en el paquete `usn`. Se extraen a
paquetes neutrales para que tanto `usn` como `mft` los consuman (una sola fuente de verdad,
evita duplicar ~80 líneas):

- `internal/winfs/fsforensic/` — `HasForensicExtension(name) bool`, `IsSuspiciousName(name) bool`,
  y las tablas `forensicExts` / `suspiciousMarkers`.
- `internal/winfs/ntfspath/` — `type ParentEntry struct{ Name string; ParentRef uint64 }` y
  `ResolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string`.

`usn` pasa a delegar en estos paquetes (adaptando sus llamadas internas); sus tests existentes
deben seguir en verde. Es refactor justificado sobre código que se está tocando, no scope
creep. La razón USN y demás lógica específica de journal permanecen en `usn`.

## Modelo de datos y parsing (puro)

```go
// Timestamps son los 4 tiempos NTFS de un atributo SI o FN.
type Timestamps struct {
    Created    time.Time
    Modified   time.Time
    MFTChanged time.Time
    Accessed   time.Time
}

// Record es un registro FILE del MFT ya parseado (solo lo relevante para timestomping).
type Record struct {
    InUse    bool       // flag 0x0001 del header FILE
    IsDir    bool       // flag 0x0002 del header FILE
    SI       Timestamps // de $STANDARD_INFORMATION (0x10)
    FN       Timestamps // de $FILE_NAME (0x30)
    HasSI    bool       // el registro contenía $SI
    HasFN    bool       // el registro contenía $FN
    FileName string     // del $FN
}

// parseRecord valida la firma "FILE", aplica el update sequence array fixup, recorre la lista
// de atributos residentes hasta el terminador 0xFFFFFFFF y extrae SI y FN.
func parseRecord(buf []byte) (Record, error)
```

**Detalles de parsing:**

- **Firma:** los primeros 4 bytes deben ser `FILE` (`0x46494C45`). Otro valor → error.
- **Update Sequence Array (fixup):** el header apunta (offset 0x04 = USA offset, 0x06 = USA
  count) a un array donde el primer `uint16` es el número de secuencia y los siguientes son los
  bytes originales de los últimos 2 bytes de cada sector (512 B). Antes de parsear atributos se
  restauran esos bytes en el buffer, o los offsets salen corruptos.
- **Flags** (offset 0x16 del header): bit 0 = InUse, bit 1 = IsDirectory.
- **Primer atributo:** offset 0x14 del header apunta al primer atributo.
- **Recorrido de atributos:** cada atributo empieza con `type (uint32)` y `length (uint32)`.
  Se avanza `length` bytes hasta encontrar `type == 0xFFFFFFFF` (terminador). Solo se procesan
  atributos **residentes** (los que interesan lo son siempre). Para SI (0x10) y FN (0x30) se lee
  el `content offset (uint16 @0x14)` y `content length (uint32 @0x10)` del atributo residente.
- **`$SI` (0x10):** los 4 timestamps FILETIME están en offsets 0x00, 0x08, 0x10, 0x18 del
  contenido (Created, Modified, MFTChanged, Accessed).
- **`$FN` (0x30):** los 4 timestamps FILETIME están en offsets 0x08, 0x10, 0x18, 0x20 del
  contenido; al final está el nombre — longitud (`uint8` @0x40), *namespace* (`uint8` @0x41),
  luego el nombre en UTF-16LE desde 0x42. Un registro puede tener varios `$FN` (nombres 8.3 y
  largos); se descarta el namespace 2 (DOS/8.3) y se prefiere el Win32/POSIX/Win32&DOS
  (namespace 1, 0 o 3), tomando sus timestamps y nombre.

## Regla de detección de timestomping (pura)

```go
type Verdict struct {
    Stomped      bool
    Reasons      []string // p.ej. "SI.Created anterior a FN.Created"
    SubSecZeroed bool     // heurística secundaria (eleva confianza, no gatilla sola)
}

func detectTimestomp(si, fn Timestamps) Verdict
```

**Semántica clave:** los timestamps de `$FN` se fijan al crear la *entrada de nombre*
(creación, rename o hardlink) y el kernel **NO los actualiza** en escrituras normales. Por eso:

- Es **normal** `SI.Modified > FN.Modified` (archivo modificado tras crearse) → no se marca.
- Es **naturalmente imposible** `SI.Created < FN.Created` → no se puede crear un archivo antes
  que su propia entrada de nombre. Firma canónica del *backdating*.

**Reglas (conservadoras, bajo falso positivo):**

1. **Gatillo principal:** `SI.Created < FN.Created` con tolerancia de 1s (evita ruido de
   resolución) → `Stomped = true`, razón `"SI.Created anterior a FN.Created"`.
2. **Gatillo secundario:** `SI.Modified < FN.Created` (mismo margen) → `Stomped = true`, razón
   `"SI.Modified anterior a FN.Created"`.
3. **Señal de confianza (no gatilla sola):** sub-segundos de `SI.Created` o `SI.Modified` en
   cero exacto (`.0000000`) mientras el timestamp no es cero → `SubSecZeroed = true`. Típico de
   tiempos seteados por API. Se usa para elevar severidad en Fase 4.

Timestamps cero (no presentes) no gatillan ninguna regla.

## Enumeración, orquestación y resolución de ruta (Windows)

```go
// Finding es una detección de timestomping lista para reportar.
type Finding struct {
    FullPath string
    FileName string
    SI       Timestamps
    FN       Timestamps
    Verdict  Verdict
}

var ErrUnsupported = errors.New("MFT solo disponible en Windows")

func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error)
```

Flujo en `mft_windows.go`:

1. Abrir handle read-only a `\\.\C:` (mismo patrón `CreateFile` que USN:
   `GENERIC_READ`, `FILE_SHARE_READ|WRITE`, `OPEN_EXISTING`).
2. **Una** pasada `ENUM_USN_DATA` que hace doble trabajo: (a) construye el mapa
   `parentRef → ntfspath.ParentEntry` para resolución de ruta, y (b) recolecta los *file refs*
   cuyo nombre pasa el filtro forense (`fsforensic.HasForensicExtension` o `IsSuspiciousName`).
3. Para cada ref candidato: `FSCTL_GET_NTFS_FILE_RECORD` (code `0x00090068`) →
   `parseRecord` → `detectTimestomp`.
4. Solo los `Stomped` se emiten como `Finding`, con ruta resuelta vía
   `ntfspath.ResolvePath(parentMap, parentRef, fileName)`.
5. `context` cancelable en los bucles (patrón de 3A).

`FSCTL_GET_NTFS_FILE_RECORD` entrada: `NTFS_FILE_RECORD_INPUT_BUFFER` = FileReferenceNumber
(uint64). Salida: `NTFS_FILE_RECORD_OUTPUT_BUFFER` = FileReferenceNumber (uint64) +
FileRecordLength (uint32) + FileRecordBuffer (bytes del registro FILE, con fixup sin aplicar).

## Colector y registro

```go
// internal/collector/mft/mft.go  (//go:build windows)
type Collector struct { Volume string }
func New() *Collector               // Volume default \\.\C:
func (c *Collector) Name() string   // "mft_timestomp"
func (c *Collector) Priority() int  // collector.PriorityDisk
func (c *Collector) Collect(ctx) ([]collector.Artifact, error)
```

`Collect` llama `ScanTimestomp`; cada `Finding` → `Artifact{Type:"mft_timestomp",
Source:FullPath, Data:JSON(finding), Collected:now}`. Se registra en
`internal/agent/live_windows.go` junto a los demás colectores de disco.

## Manejo de errores y privacidad

- **Degradación:** cualquier fallo (sin elevación, FSCTL no soportado, volumen no NTFS) →
  `error` que el runner convierte en `Finding` INFO. Un colector nunca tumba el escaneo.
- **Privacidad:** solo metadatos forenses (ruta de ejecutables/scripts, timestamps, razón).
  Nunca contenido ni nombres de archivos personales — el filtro forense lo garantiza.

## Estrategia de testing

- **Tests puros (cross-platform):**
  - `parseRecord`: registros FILE sintéticos, incluyendo un helper que construye el update
    sequence array y lo aplica al revés, para verificar el fixup; casos con SI+FN, solo SI,
    firma inválida, atributos truncados.
  - `detectTimestomp`: matriz de casos — normal (sin marca), backdating `SI.Created<FN.Created`,
    modificado-antes-de-crear `SI.Modified<FN.Created`, sub-segundos en cero, timestamps cero.
- **Test de integración (`//go:build windows`):** `ScanTimestomp` sobre `\\.\C:`, valida forma
  (todo `Finding` tiene `FullPath` no vacío y `Verdict.Stomped`) con `Skip` si no hay
  elevación / journal inactivo / FSCTL no soportado.
- **Build:** `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...` y `go vet` limpios.

## Restricciones globales (heredadas)

- Target `GOOS=windows GOARCH=amd64`, **sin CGO**.
- Go 1.22+. Module path `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime.
- Identificadores en inglés; comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Fuera de alcance (queda para 3B-2)

- Acceso raw a `\\.\C:` (boot sector `$Boot`, data runs del `$MFT`, lectura por sector).
- Decodificación de data runs de `$DATA` (residente y no-residente).
- Enumeración/recuperación de entradas borradas (registros con `InUse = 0` que
  `ENUM_USN_DATA` no lista).
- Resolución de ruta completa post-borrado desde el árbol de directorios del MFT.
