# Agente Forense Windows — Fase 3B-1 (Fundación MFT + Detección de Timestomping) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detectar manipulación de timestamps (*timestomping*) en ejecutables/scripts del volumen `C:` comparando los timestamps de `$STANDARD_INFORMATION` (SI) contra `$FILE_NAME` (FN) de cada registro MFT, y reportar cada detección como artefacto forense con ruta completa.

**Architecture:** Enfoque híbrido: se reutiliza `ENUM_USN_DATA` (de 3A) para enumerar el MFT una vez y filtrar a archivos forenses; para cada candidato se pide su registro MFT con `FSCTL_GET_NTFS_FILE_RECORD` y se parsea. `$SI` y `$FN` son siempre residentes, así que **no** hace falta decodificar data runs (eso queda para 3B-2). El parseo de registros MFT y la detección son funciones puras (testeables en cualquier host); solo `mft_windows.go` toca syscalls. Antes se extraen dos helpers hoy duplicables desde el paquete `usn`: el filtro forense y la resolución de ruta.

**Tech Stack:** Go 1.22+, `golang.org/x/sys/windows` (DeviceIoControl, CreateFile), stdlib (`encoding/binary`, `unicode/utf16`). Sin CGO, sin dependencias externas en runtime.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Go 1.22+ como mínimo. Module path: `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime (stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` INFO (el `runner` recupera panics y propaga errores).
- Nunca recolectar contenido ni nombres de archivos personales: solo metadatos forenses (rutas de ejecutables/scripts, timestamps, razones). El filtro forense lo garantiza.
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Estructura de archivos

- `internal/winfs/fsforensic/fsforensic.go` — filtro forense compartido (extraído de `usn`).
- `internal/winfs/ntfspath/ntfspath.go` — resolución de ruta desde mapa de padres (extraído de `usn`).
- `internal/winfs/mft/record.go` — parseo puro de registros FILE del MFT (fixup + atributos SI/FN).
- `internal/winfs/mft/timestomp.go` — detección pura de timestomping.
- `internal/winfs/mft/mft_windows.go` — enumeración + `FSCTL_GET_NTFS_FILE_RECORD` + orquestación.
- `internal/winfs/mft/mft_other.go` — stub no-Windows.
- `internal/collector/mft/mft.go` — adaptador al contrato `collector.Collector`.

---

### Task 1: Extraer filtro forense compartido `fsforensic`

**Files:**
- Create: `internal/winfs/fsforensic/fsforensic.go`
- Test: `internal/winfs/fsforensic/fsforensic_test.go`
- Modify: `internal/winfs/usn/filter.go` (quitar filtro, dejar solo lo específico de USN)
- Modify: `internal/winfs/usn/filter_test.go` (quitar tests movidos)
- Modify: `internal/winfs/usn/usn_windows.go` (delegar en `fsforensic`)
- Modify: `internal/winfs/usn/usn_windows_test.go` (delegar en `fsforensic`)

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func HasForensicExtension(name string) bool`
  - `func IsSuspiciousName(name string) bool`

- [ ] **Step 1: Escribir el test del nuevo paquete**

```go
// internal/winfs/fsforensic/fsforensic_test.go
package fsforensic

import "testing"

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

func TestIsSuspiciousName(t *testing.T) {
	if !IsSuspiciousName("FreeFire_Injector.exe") {
		t.Error("esperaba sospechoso para nombre con 'inject'")
	}
	if IsSuspiciousName("notepad.exe") {
		t.Error("notepad.exe no debería ser sospechoso")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/fsforensic/`
Expected: FAIL de compilación — `undefined: HasForensicExtension`.

- [ ] **Step 3: Escribir `fsforensic.go`**

```go
// internal/winfs/fsforensic/fsforensic.go
package fsforensic

import (
	"path/filepath"
	"strings"
)

// forensicExts son las extensiones de ejecutables/scripts que se retienen.
var forensicExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".bat": true, ".ps1": true,
	".cmd": true, ".vbs": true, ".scr": true, ".msi": true,
}

// suspiciousMarkers son subcadenas que suben la sospecha de un nombre (heurística
// para severidad; hoy solo marca el flag, la severidad real llega en Fase 4).
var suspiciousMarkers = []string{
	"cheat", "inject", "loader", "bypass", "aimbot", "macro",
	"esp", "hook", "wipe", "ccleaner", "bleachbit",
}

// HasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func HasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// IsSuspiciousName reporta si el nombre contiene un marcador sospechoso.
func IsSuspiciousName(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range suspiciousMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Correr el test para verificar que pasa**

Run: `go test ./internal/winfs/fsforensic/`
Expected: PASS.

- [ ] **Step 5: Reemplazar `usn/filter.go` (dejar solo lo específico de USN)**

Reemplazar el contenido completo de `internal/winfs/usn/filter.go` por:
```go
// internal/winfs/usn/filter.go
package usn

// relevantReasonMask agrega las razones USN forensicamente significativas.
const relevantReasonMask = ReasonDataOverwrite | ReasonDataTruncation |
	ReasonFileCreate | ReasonFileDelete | ReasonRenameOldName | ReasonRenameNewName

// reasonIsRelevant reporta si la máscara de razones incluye alguna relevante.
func reasonIsRelevant(reason uint32) bool {
	return reason&relevantReasonMask != 0
}
```

- [ ] **Step 6: Reemplazar `usn/filter_test.go` (dejar solo el test de razón)**

Reemplazar el contenido completo de `internal/winfs/usn/filter_test.go` por:
```go
// internal/winfs/usn/filter_test.go
package usn

import "testing"

func TestReasonIsRelevant(t *testing.T) {
	if !reasonIsRelevant(ReasonFileDelete) {
		t.Error("FileDelete debería ser relevante")
	}
	if reasonIsRelevant(0x80000000) { // USN_REASON_CLOSE, no relevante por sí solo
		t.Error("CLOSE-solo no debería ser relevante")
	}
}
```

- [ ] **Step 7: Actualizar `usn/usn_windows.go` para delegar en `fsforensic`**

En el bloque de imports de `internal/winfs/usn/usn_windows.go`, agregar:
```go
	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
```
En `readRecords`, reemplazar el bloque de filtrado por nombre:
```go
			suspicious := isSuspiciousName(rec.FileName)
			if !hasForensicExtension(rec.FileName) && !suspicious {
				continue
			}
```
por:
```go
			suspicious := fsforensic.IsSuspiciousName(rec.FileName)
			if !fsforensic.HasForensicExtension(rec.FileName) && !suspicious {
				continue
			}
```

- [ ] **Step 8: Actualizar `usn/usn_windows_test.go` para delegar en `fsforensic`**

En `internal/winfs/usn/usn_windows_test.go`, agregar al import:
```go
	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
```
Reemplazar la línea:
```go
		if !hasForensicExtension(e.FileName) && !isSuspiciousName(e.FileName) {
```
por:
```go
		if !fsforensic.HasForensicExtension(e.FileName) && !fsforensic.IsSuspiciousName(e.FileName) {
```

- [ ] **Step 9: Correr todos los tests afectados y el build de Windows**

Run: `go test ./internal/winfs/fsforensic/ ./internal/winfs/usn/`
Expected: PASS.
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.

- [ ] **Step 10: Commit**

```bash
git add internal/winfs/fsforensic/ internal/winfs/usn/filter.go internal/winfs/usn/filter_test.go internal/winfs/usn/usn_windows.go internal/winfs/usn/usn_windows_test.go
git commit -m "refactor: extraer fsforensic (filtro compartido) desde usn"
```

---

### Task 2: Extraer resolución de ruta compartida `ntfspath`

**Files:**
- Create: `internal/winfs/ntfspath/ntfspath.go`
- Test: `internal/winfs/ntfspath/ntfspath_test.go`
- Delete: `internal/winfs/usn/path.go` (movido a `ntfspath`)
- Delete: `internal/winfs/usn/path_test.go` (movido a `ntfspath`)
- Modify: `internal/winfs/usn/usn_windows.go` (usar `ntfspath.ParentEntry` / `ntfspath.ResolvePath`)

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type ParentEntry struct { Name string; ParentRef uint64 }`
  - `func ResolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string`

- [ ] **Step 1: Escribir el test del nuevo paquete**

```go
// internal/winfs/ntfspath/ntfspath_test.go
package ntfspath

import "testing"

// testRootRef simula el FileRef de la raíz del volumen (nº de entrada MFT 5).
const testRootRef = 0x0005000000000005

func TestResolvePathFull(t *testing.T) {
	pm := map[uint64]ParentEntry{
		100: {Name: "Users", ParentRef: testRootRef},
		200: {Name: "Downloads", ParentRef: 100},
	}
	got := ResolvePath(pm, 200, "cheat.exe")
	want := `\Users\Downloads\cheat.exe`
	if got != want {
		t.Fatalf("ResolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathMissingParent(t *testing.T) {
	got := ResolvePath(map[uint64]ParentEntry{}, 999, "evil.exe")
	want := `\` + unresolvedPrefix + `\evil.exe`
	if got != want {
		t.Fatalf("ResolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathAtRoot(t *testing.T) {
	got := ResolvePath(map[uint64]ParentEntry{}, testRootRef, "pagefile.sys")
	if got != `\pagefile.sys` {
		t.Fatalf("ResolvePath = %q, want %q", got, `\pagefile.sys`)
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/ntfspath/`
Expected: FAIL de compilación — `undefined: ResolvePath`, `undefined: ParentEntry`.

- [ ] **Step 3: Escribir `ntfspath.go`**

```go
// internal/winfs/ntfspath/ntfspath.go
package ntfspath

import "strings"

// ParentEntry es una fila del mapa de rutas construido con ENUM_USN_DATA.
type ParentEntry struct {
	Name      string
	ParentRef uint64
}

const (
	// unresolvedPrefix marca un tramo de ruta cuyo directorio padre ya no existe
	// (p.ej. un archivo borrado cuyo padre también fue borrado).
	unresolvedPrefix = "<sin-resolver>"

	// rootRecordNumber es el nº de entrada MFT de la raíz del volumen NTFS.
	rootRecordNumber = 5

	// maxDepth acota la subida para evitar ciclos en mapas corruptos.
	maxDepth = 256
)

// isRoot compara solo los 48 bits bajos (nº de entrada MFT) para ignorar la
// secuencia, que puede variar entre snapshots.
func isRoot(ref uint64) bool {
	return ref&0x0000FFFFFFFFFFFF == rootRecordNumber
}

// ResolvePath reconstruye la ruta absoluta subiendo por parentMap desde
// parentRef. Corta en la raíz; si un padre falta, antepone unresolvedPrefix.
func ResolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string {
	parts := []string{leaf}
	ref := parentRef
	for depth := 0; depth < maxDepth; depth++ {
		if isRoot(ref) {
			break
		}
		entry, ok := parentMap[ref]
		if !ok {
			parts = append(parts, unresolvedPrefix)
			break
		}
		parts = append(parts, entry.Name)
		ref = entry.ParentRef
	}
	// parts está de hoja a raíz; invertir para raíz→hoja.
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return `\` + strings.Join(parts, `\`)
}
```

- [ ] **Step 4: Correr el test para verificar que pasa**

Run: `go test ./internal/winfs/ntfspath/`
Expected: PASS.

- [ ] **Step 5: Borrar los archivos movidos de `usn`**

```bash
git rm internal/winfs/usn/path.go internal/winfs/usn/path_test.go
```

- [ ] **Step 6: Actualizar `usn/usn_windows.go` para usar `ntfspath`**

En el bloque de imports de `internal/winfs/usn/usn_windows.go`, agregar:
```go
	"github.com/telagem/agent-windows/internal/winfs/ntfspath"
```
Cambiar la firma de `enumParents` para devolver el tipo de `ntfspath`:
```go
func enumParents(ctx context.Context, h windows.Handle) (map[uint64]ntfspath.ParentEntry, error) {
	parentMap := make(map[uint64]ntfspath.ParentEntry)
```
Dentro de `enumParents`, reemplazar la asignación al mapa:
```go
			if perr == nil {
				parentMap[rec.FileRef] = ntfspath.ParentEntry{Name: rec.FileName, ParentRef: rec.ParentRef}
			}
```
Cambiar la firma de `readRecords`:
```go
func readRecords(ctx context.Context, h windows.Handle, journalID uint64, parentMap map[uint64]ntfspath.ParentEntry) ([]Entry, error) {
```
Dentro de `readRecords`, reemplazar la llamada `resolvePath(...)`:
```go
				FullPath:   ntfspath.ResolvePath(parentMap, rec.ParentRef, rec.FileName),
```

- [ ] **Step 7: Correr todos los tests afectados y el build de Windows**

Run: `go test ./internal/winfs/ntfspath/ ./internal/winfs/usn/`
Expected: PASS.
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./internal/winfs/usn/`
Expected: sin advertencias.

- [ ] **Step 8: Commit**

```bash
git add internal/winfs/ntfspath/ internal/winfs/usn/usn_windows.go
git rm internal/winfs/usn/path.go internal/winfs/usn/path_test.go
git commit -m "refactor: extraer ntfspath (resolución de ruta) desde usn"
```

---

### Task 3: Parseo puro de registros MFT (`record.go`)

**Files:**
- Create: `internal/winfs/mft/record.go`
- Test: `internal/winfs/mft/record_test.go`

**Interfaces:**
- Consumes: `wintime.FiletimeToTime`.
- Produces:
  - `type Timestamps struct { Created, Modified, MFTChanged, Accessed time.Time }`
  - `type Record struct { InUse bool; IsDir bool; SI Timestamps; FN Timestamps; HasSI bool; HasFN bool; FileName string }`
  - `func parseRecord(buf []byte) (Record, error)` — valida firma `FILE`, aplica el update sequence array fixup, recorre atributos residentes y extrae SI (0x10) y FN (0x30).

- [ ] **Step 1: Escribir el test que falla (con helpers de construcción)**

```go
// internal/winfs/mft/record_test.go
package mft

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildAttr arma un atributo residente (header 0x18 + contenido, alineado a 8).
func buildAttr(attrType uint32, content []byte) []byte {
	const hdr = 0x18
	total := hdr + len(content)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 0 // residente
	binary.LittleEndian.PutUint32(a[0x10:0x14], uint32(len(content)))
	binary.LittleEndian.PutUint16(a[0x14:0x16], hdr)
	copy(a[hdr:], content)
	return a
}

// siContent arma el contenido de un $STANDARD_INFORMATION (0x48 bytes).
func siContent(created, modified, mftChanged, accessed uint64) []byte {
	c := make([]byte, 0x48)
	binary.LittleEndian.PutUint64(c[0x00:], created)
	binary.LittleEndian.PutUint64(c[0x08:], modified)
	binary.LittleEndian.PutUint64(c[0x10:], mftChanged)
	binary.LittleEndian.PutUint64(c[0x18:], accessed)
	return c
}

// fnContent arma el contenido de un $FILE_NAME con nombre UTF-16.
func fnContent(created, modified, mftChanged, accessed uint64, namespace byte, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	c := make([]byte, 0x42+len(u16)*2)
	binary.LittleEndian.PutUint64(c[0x08:], created)
	binary.LittleEndian.PutUint64(c[0x10:], modified)
	binary.LittleEndian.PutUint64(c[0x18:], mftChanged)
	binary.LittleEndian.PutUint64(c[0x20:], accessed)
	c[0x40] = byte(len(u16))
	c[0x41] = namespace
	for i, ch := range u16 {
		binary.LittleEndian.PutUint16(c[0x42+i*2:], ch)
	}
	return c
}

// buildRecord arma un registro FILE de 1024 bytes con el fixup "en disco"
// aplicado (bytes de fin de sector reemplazados por el número de secuencia).
func buildRecord(flags uint16, attrs ...[]byte) []byte {
	const (
		size      = 1024
		usaOff    = 0x30
		usaCount  = 3 // 1 secuencia + 2 sectores
		firstAttr = 0x38
		seq       = 0x0001
	)
	buf := make([]byte, size)
	copy(buf[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(buf[0x04:], usaOff)
	binary.LittleEndian.PutUint16(buf[0x06:], usaCount)
	binary.LittleEndian.PutUint16(buf[0x14:], firstAttr)
	binary.LittleEndian.PutUint16(buf[0x16:], flags)
	off := firstAttr
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}
	binary.LittleEndian.PutUint32(buf[off:], 0xFFFFFFFF) // terminador de atributos
	// Simular el fixup: guardar los bytes reales de fin de sector en la USA y
	// escribir el número de secuencia en su lugar.
	binary.LittleEndian.PutUint16(buf[usaOff:], seq)
	for i := 0; i < usaCount-1; i++ {
		sectorEnd := (i+1)*512 - 2
		orig := binary.LittleEndian.Uint16(buf[sectorEnd : sectorEnd+2])
		binary.LittleEndian.PutUint16(buf[usaOff+2*(i+1):], orig)
		binary.LittleEndian.PutUint16(buf[sectorEnd:], seq)
	}
	return buf
}

const ftKnown = 0x01D9553EC1174000 // 2023-03-13T00:00:00Z

func TestParseRecordExtractsSIandFN(t *testing.T) {
	si := siContent(ftKnown, ftKnown+10, ftKnown, ftKnown)
	fn := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "cheat.exe")
	buf := buildRecord(0x0001, buildAttr(0x10, si), buildAttr(0x30, fn))
	rec, err := parseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if !rec.InUse {
		t.Error("InUse debería ser true")
	}
	if !rec.HasSI || !rec.HasFN {
		t.Fatalf("faltan SI(%v) o FN(%v)", rec.HasSI, rec.HasFN)
	}
	if rec.FileName != "cheat.exe" {
		t.Errorf("FileName = %q, want cheat.exe", rec.FileName)
	}
	if rec.SI.Created.IsZero() || rec.FN.Created.IsZero() {
		t.Error("timestamps no deberían ser cero")
	}
}

func TestParseRecordBadSignature(t *testing.T) {
	buf := buildRecord(0x0001, buildAttr(0x10, siContent(ftKnown, ftKnown, ftKnown, ftKnown)))
	buf[0] = 'X' // rompe la firma "FILE"
	if _, err := parseRecord(buf); err == nil {
		t.Fatal("esperaba error con firma inválida")
	}
}

func TestParseRecordPrefersLongName(t *testing.T) {
	long := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "cheatengine.exe")
	dos := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 2, "CHEAT~1.EXE")
	buf := buildRecord(0x0001, buildAttr(0x30, long), buildAttr(0x30, dos))
	rec, err := parseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if rec.FileName != "cheatengine.exe" {
		t.Errorf("FileName = %q, want cheatengine.exe (no el 8.3)", rec.FileName)
	}
}

func TestParseRecordFixupMismatch(t *testing.T) {
	buf := buildRecord(0x0001, buildAttr(0x10, siContent(ftKnown, ftKnown, ftKnown, ftKnown)))
	buf[0x1FE] ^= 0xFF // corrompe el fin del primer sector
	if _, err := parseRecord(buf); err == nil {
		t.Fatal("esperaba error por número de secuencia que no coincide")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/mft/`
Expected: FAIL de compilación — `undefined: parseRecord`, `undefined: Record`, etc.

- [ ] **Step 3: Escribir `record.go`**

```go
// internal/winfs/mft/record.go
package mft

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"

	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Timestamps son los 4 tiempos NTFS de un atributo SI o FN.
type Timestamps struct {
	Created    time.Time
	Modified   time.Time
	MFTChanged time.Time
	Accessed   time.Time
}

// Record es un registro FILE del MFT ya parseado (solo lo relevante para timestomping).
type Record struct {
	InUse    bool // flag 0x0001 del header FILE
	IsDir    bool // flag 0x0002 del header FILE
	SI       Timestamps
	FN       Timestamps
	HasSI    bool
	HasFN    bool
	FileName string

	fnNamespace byte // namespace del $FN ya tomado (para preferir el nombre largo)
}

const (
	fileSignature  = 0x454C4946 // "FILE" en little-endian
	attrStandardInfo = 0x10
	attrFileName     = 0x30
	attrTerminator   = 0xFFFFFFFF
	sectorSize       = 512
	dosNamespace     = 2 // namespace 8.3
)

// ErrBadSignature indica que el buffer no empieza con la firma "FILE".
var ErrBadSignature = errors.New("registro MFT sin firma FILE")

// parseRecord parsea un registro FILE del MFT: valida firma, aplica el update
// sequence array fixup y extrae SI (0x10) y FN (0x30) de los atributos residentes.
func parseRecord(buf []byte) (Record, error) {
	if len(buf) < 0x30 {
		return Record{}, errors.New("registro MFT truncado")
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != fileSignature {
		return Record{}, ErrBadSignature
	}
	fixed, err := applyFixup(buf)
	if err != nil {
		return Record{}, err
	}
	flags := binary.LittleEndian.Uint16(fixed[0x16:0x18])
	rec := Record{
		InUse: flags&0x01 != 0,
		IsDir: flags&0x02 != 0,
	}
	firstAttr := int(binary.LittleEndian.Uint16(fixed[0x14:0x16]))
	if err := rec.parseAttributes(fixed, firstAttr); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// applyFixup restaura los últimos 2 bytes de cada sector, que NTFS reemplaza por
// el update sequence number al escribir. Devuelve una copia corregida del buffer.
func applyFixup(buf []byte) ([]byte, error) {
	usaOff := int(binary.LittleEndian.Uint16(buf[0x04:0x06]))
	usaCount := int(binary.LittleEndian.Uint16(buf[0x06:0x08]))
	if usaCount == 0 || usaOff+usaCount*2 > len(buf) {
		return nil, errors.New("update sequence array inválido")
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	seq := binary.LittleEndian.Uint16(out[usaOff : usaOff+2])
	for i := 0; i < usaCount-1; i++ {
		sectorEnd := (i+1)*sectorSize - 2
		if sectorEnd+2 > len(out) {
			return nil, errors.New("sector fuera de rango en fixup")
		}
		if binary.LittleEndian.Uint16(out[sectorEnd:sectorEnd+2]) != seq {
			return nil, errors.New("update sequence number no coincide (registro corrupto)")
		}
		orig := out[usaOff+2*(i+1) : usaOff+2*(i+1)+2]
		copy(out[sectorEnd:sectorEnd+2], orig)
	}
	return out, nil
}

// parseAttributes recorre la lista de atributos desde off hasta el terminador,
// procesando solo los residentes SI y FN.
func (r *Record) parseAttributes(buf []byte, off int) error {
	for off+8 <= len(buf) {
		attrType := binary.LittleEndian.Uint32(buf[off : off+4])
		if attrType == attrTerminator {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(buf[off+4 : off+8]))
		if attrLen < 0x18 || off+attrLen > len(buf) {
			return errors.New("longitud de atributo inválida")
		}
		if buf[off+8] == 0 { // no-resident flag == 0 → residente
			contentLen := int(binary.LittleEndian.Uint32(buf[off+0x10 : off+0x14]))
			contentOff := int(binary.LittleEndian.Uint16(buf[off+0x14 : off+0x16]))
			start := off + contentOff
			if contentLen > 0 && start+contentLen <= len(buf) {
				content := buf[start : start+contentLen]
				switch attrType {
				case attrStandardInfo:
					r.SI = parseTimestamps(content, 0x00)
					r.HasSI = true
				case attrFileName:
					r.applyFileName(content)
				}
			}
		}
		off += attrLen
	}
	return nil
}

// parseTimestamps lee los 4 FILETIME consecutivos a partir de base.
func parseTimestamps(c []byte, base int) Timestamps {
	if base+0x20 > len(c) {
		return Timestamps{}
	}
	return Timestamps{
		Created:    wintime.FiletimeToTime(binary.LittleEndian.Uint64(c[base+0x00 : base+0x08])),
		Modified:   wintime.FiletimeToTime(binary.LittleEndian.Uint64(c[base+0x08 : base+0x10])),
		MFTChanged: wintime.FiletimeToTime(binary.LittleEndian.Uint64(c[base+0x10 : base+0x18])),
		Accessed:   wintime.FiletimeToTime(binary.LittleEndian.Uint64(c[base+0x18 : base+0x20])),
	}
}

// applyFileName parsea un $FILE_NAME. Los timestamps arrancan en 0x08 (tras el
// parent ref). Prefiere el nombre no-DOS: si ya hay un FN no-8.3, ignora un 8.3.
func (r *Record) applyFileName(c []byte) {
	if len(c) < 0x42 {
		return
	}
	namespace := c[0x41]
	if r.HasFN && r.fnNamespace != dosNamespace && namespace == dosNamespace {
		return
	}
	nameLen := int(c[0x40])
	nameEnd := 0x42 + nameLen*2
	if nameEnd > len(c) {
		nameEnd = len(c)
	}
	r.FN = parseTimestamps(c, 0x08)
	r.FileName = decodeUTF16(c[0x42:nameEnd])
	r.HasFN = true
	r.fnNamespace = namespace
}

// decodeUTF16 decodifica bytes UTF-16LE a string.
func decodeUTF16(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u16))
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/mft/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/mft/record.go internal/winfs/mft/record_test.go
git commit -m "feat: parseo puro de registros MFT (fixup + atributos SI/FN)"
```

---

### Task 4: Detección de timestomping (`timestomp.go`)

**Files:**
- Create: `internal/winfs/mft/timestomp.go`
- Test: `internal/winfs/mft/timestomp_test.go`

**Interfaces:**
- Consumes: `Timestamps` (Task 3).
- Produces:
  - `type Verdict struct { Stomped bool; Reasons []string; SubSecZeroed bool }`
  - `func detectTimestomp(si, fn Timestamps) Verdict`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/mft/timestomp_test.go
package mft

import (
	"testing"
	"time"
)

func TestDetectNormalNotStomped(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 500, time.UTC)
	si := Timestamps{Created: base, Modified: base.Add(time.Hour), MFTChanged: base, Accessed: base}
	fn := Timestamps{Created: base, Modified: base, MFTChanged: base, Accessed: base}
	if v := detectTimestomp(si, fn); v.Stomped {
		t.Errorf("archivo normal no debería marcarse: %+v", v)
	}
}

func TestDetectBackdatedCreated(t *testing.T) {
	fnCreated := time.Date(2026, 1, 1, 12, 0, 0, 300, time.UTC)
	si := Timestamps{Created: fnCreated.Add(-48 * time.Hour), Modified: fnCreated}
	fn := Timestamps{Created: fnCreated}
	v := detectTimestomp(si, fn)
	if !v.Stomped {
		t.Fatal("backdating (SI.Created < FN.Created) debería marcarse")
	}
	if len(v.Reasons) == 0 {
		t.Error("esperaba al menos una razón")
	}
}

func TestDetectModifiedBeforeName(t *testing.T) {
	fnCreated := time.Date(2026, 1, 1, 12, 0, 0, 300, time.UTC)
	si := Timestamps{Created: fnCreated, Modified: fnCreated.Add(-10 * time.Hour)}
	fn := Timestamps{Created: fnCreated}
	if !detectTimestomp(si, fn).Stomped {
		t.Fatal("SI.Modified < FN.Created debería marcarse")
	}
}

func TestDetectSubSecZeroed(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) // sub-segundo exactamente 0
	si := Timestamps{Created: base, Modified: base}
	fn := Timestamps{Created: base, Modified: base}
	if !detectTimestomp(si, fn).SubSecZeroed {
		t.Error("esperaba SubSecZeroed con sub-segundos en cero")
	}
}

func TestDetectZeroTimestampsNotStomped(t *testing.T) {
	if detectTimestomp(Timestamps{}, Timestamps{}).Stomped {
		t.Error("timestamps cero no deberían gatillar detección")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/mft/ -run TestDetect`
Expected: FAIL de compilación — `undefined: detectTimestomp`, `undefined: Verdict`.

- [ ] **Step 3: Escribir `timestomp.go`**

```go
// internal/winfs/mft/timestomp.go
package mft

import "time"

// stompTolerance absorbe diferencias menores de resolución al comparar timestamps.
const stompTolerance = time.Second

// Verdict es el resultado de evaluar timestomping sobre un registro.
type Verdict struct {
	Stomped      bool
	Reasons      []string
	SubSecZeroed bool // heurística de confianza; no gatilla por sí sola
}

// detectTimestomp compara SI vs FN. Marca backdating imposible naturalmente:
// SI.Created (o SI.Modified) anterior a FN.Created, que es cuando se creó la
// entrada de nombre. Los ceros (timestamps ausentes) no gatillan.
func detectTimestomp(si, fn Timestamps) Verdict {
	var v Verdict
	if isBefore(si.Created, fn.Created) {
		v.Stomped = true
		v.Reasons = append(v.Reasons, "SI.Created anterior a FN.Created")
	}
	if isBefore(si.Modified, fn.Created) {
		v.Stomped = true
		v.Reasons = append(v.Reasons, "SI.Modified anterior a FN.Created")
	}
	if subSecZeroed(si.Created) || subSecZeroed(si.Modified) {
		v.SubSecZeroed = true
	}
	return v
}

// isBefore reporta si a precede a b por más de la tolerancia. Ignora ceros.
func isBefore(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	return a.Add(stompTolerance).Before(b)
}

// subSecZeroed reporta si t no es cero pero su parte sub-segundo es exactamente
// 0 — típico de tiempos seteados por API (los naturales tienen resolución 100ns).
func subSecZeroed(t time.Time) bool {
	return !t.IsZero() && t.Nanosecond() == 0
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/mft/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/mft/timestomp.go internal/winfs/mft/timestomp_test.go
git commit -m "feat: detección pura de timestomping (SI vs FN)"
```

---

### Task 5: Scan real vía FSCTL (`mft_windows.go` / `mft_other.go`)

**Files:**
- Create: `internal/winfs/mft/mft_windows.go`
- Create: `internal/winfs/mft/mft_other.go`
- Test: `internal/winfs/mft/mft_windows_test.go`

**Interfaces:**
- Consumes: `parseRecord`, `Record`, `detectTimestomp`, `Verdict`, `Timestamps` (Tasks 3-4); `fsforensic.HasForensicExtension`, `fsforensic.IsSuspiciousName` (Task 1); `ntfspath.ParentEntry`, `ntfspath.ResolvePath` (Task 2).
- Produces:
  - `type Finding struct { FullPath string; FileName string; SI Timestamps; FN Timestamps; Verdict Verdict }`
  - `var ErrUnsupported = errors.New("MFT solo disponible en Windows")`
  - `func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error)` — enumera el MFT, filtra a forenses, pide cada registro con FSCTL, detecta timestomping. Fuera de Windows devuelve `ErrUnsupported`.

- [ ] **Step 1: Escribir el test (integración, con skip)**

```go
//go:build windows

// internal/winfs/mft/mft_windows_test.go
package mft

import (
	"context"
	"errors"
	"testing"
)

// TestScanTimestompIntegration corre solo con acceso al volumen (elevación).
// No es determinista: valida forma, no contenido.
func TestScanTimestompIntegration(t *testing.T) {
	findings, err := ScanTimestomp(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("MFT no accesible (¿sin elevación o FSCTL no soportado?): %v", err)
	}
	for _, f := range findings {
		if f.FullPath == "" {
			t.Fatalf("finding sin FullPath: %+v", f)
		}
		if !f.Verdict.Stomped {
			t.Fatalf("finding emitido sin Stomped: %+v", f)
		}
	}
}

func TestErrUnsupportedIsDefined(t *testing.T) {
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("ErrUnsupported mal definido")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/mft/`
Expected: FAIL de compilación — `undefined: ScanTimestomp`, `undefined: Finding`, `undefined: ErrUnsupported`.

- [ ] **Step 3: Escribir `mft_other.go` (stub no-Windows)**

```go
//go:build !windows

// internal/winfs/mft/mft_other.go
package mft

import (
	"context"
	"errors"
)

// ErrUnsupported se devuelve al intentar leer el MFT fuera de Windows.
var ErrUnsupported = errors.New("MFT solo disponible en Windows")

// Finding es una detección de timestomping lista para reportar.
type Finding struct {
	FullPath string
	FileName string
	SI       Timestamps
	FN       Timestamps
	Verdict  Verdict
}

// ScanTimestomp no está soportado fuera de Windows.
func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error) {
	return nil, ErrUnsupported
}
```

- [ ] **Step 4: Escribir `mft_windows.go` (FSCTL real)**

```go
//go:build windows

// internal/winfs/mft/mft_windows.go
package mft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	"github.com/telagem/agent-windows/internal/winfs/ntfspath"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows (no debería
// dispararse aquí).
var ErrUnsupported = errors.New("MFT solo disponible en Windows")

// Finding es una detección de timestomping lista para reportar.
type Finding struct {
	FullPath string
	FileName string
	SI       Timestamps
	FN       Timestamps
	Verdict  Verdict
}

// FSCTL codes (winioctl.h).
const (
	fsctlEnumUsnData       = 0x000900b3
	fsctlGetNtfsFileRecord = 0x00090068
)

// mftEntryMask aísla el nº de entrada MFT (48 bits bajos) del file reference,
// ignorando el nº de secuencia en los 16 bits altos.
const mftEntryMask = 0x0000FFFFFFFFFFFF

// ScanTimestomp abre el volumen, enumera el MFT filtrando a archivos forenses y
// evalúa timestomping en cada candidato pidiendo su registro con FSCTL.
func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error) {
	pathPtr, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return nil, fmt.Errorf("path de volumen inválido %q: %w", volume, err)
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("abrir %s: %w", volume, err)
	}
	defer windows.CloseHandle(h)

	parentMap, candidates, err := enumForensic(ctx, h)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, ref := range candidates {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		rec, err := getFileRecord(h, ref)
		if err != nil || !rec.HasSI || !rec.HasFN {
			continue
		}
		v := detectTimestomp(rec.SI, rec.FN)
		if !v.Stomped {
			continue
		}
		parentRef := parentMap[ref].ParentRef
		findings = append(findings, Finding{
			FullPath: ntfspath.ResolvePath(parentMap, parentRef, rec.FileName),
			FileName: rec.FileName,
			SI:       rec.SI,
			FN:       rec.FN,
			Verdict:  v,
		})
	}
	return findings, nil
}

// enumForensic recorre ENUM_USN_DATA una vez: construye el mapa de padres (para
// resolver rutas) y junta los file refs cuyo nombre pasa el filtro forense.
func enumForensic(ctx context.Context, h windows.Handle) (map[uint64]ntfspath.ParentEntry, []uint64, error) {
	parentMap := make(map[uint64]ntfspath.ParentEntry)
	var candidates []uint64
	// MFT_ENUM_DATA_V0: StartFileReferenceNumber(8) + LowUsn(8) + HighUsn(8).
	in := make([]byte, 24)
	binary.LittleEndian.PutUint64(in[8:16], 0)                   // LowUsn
	binary.LittleEndian.PutUint64(in[16:24], 0xFFFFFFFFFFFFFFFF) // HighUsn
	out := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return parentMap, candidates, ctx.Err()
		default:
		}
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlEnumUsnData,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return parentMap, candidates, fmt.Errorf("ENUM_USN_DATA: %w", err)
		}
		if ret <= 8 {
			break
		}
		next := binary.LittleEndian.Uint64(out[0:8])
		pos := 8
		for pos < int(ret) {
			ref, parentRef, name, n := parseEnumEntry(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			pos += n
			if name == "" {
				continue
			}
			parentMap[ref] = ntfspath.ParentEntry{Name: name, ParentRef: parentRef}
			if fsforensic.HasForensicExtension(name) || fsforensic.IsSuspiciousName(name) {
				candidates = append(candidates, ref)
			}
		}
		binary.LittleEndian.PutUint64(in[0:8], next)
	}
	return parentMap, candidates, nil
}

// parseEnumEntry extrae los campos que necesita la enumeración (fileRef,
// parentRef, nombre) de un USN_RECORD_V2/V3, devolviendo también su longitud
// para avanzar. Es una lectura mínima e intencionalmente local, para no acoplar
// mft al parser completo del journal (paquete usn). n<=0 indica fin/error.
func parseEnumEntry(buf []byte) (fileRef, parentRef uint64, name string, n int) {
	if len(buf) < 4 {
		return 0, 0, "", 0
	}
	recLen := int(binary.LittleEndian.Uint32(buf[0:4]))
	if recLen < 8 || recLen > len(buf) {
		return 0, 0, "", 0
	}
	major := binary.LittleEndian.Uint16(buf[4:6])
	var refOff, parentOff, nameLenOff, nameOffOff int
	switch major {
	case 2:
		refOff, parentOff, nameLenOff, nameOffOff = 0x08, 0x10, 0x38, 0x3A
	case 3:
		refOff, parentOff, nameLenOff, nameOffOff = 0x08, 0x18, 0x48, 0x4A
	default:
		return 0, 0, "", recLen // versión desconocida: saltear
	}
	if nameOffOff+2 > recLen {
		return 0, 0, "", recLen
	}
	fileRef = binary.LittleEndian.Uint64(buf[refOff : refOff+8])
	parentRef = binary.LittleEndian.Uint64(buf[parentOff : parentOff+8])
	nameLen := int(binary.LittleEndian.Uint16(buf[nameLenOff : nameLenOff+2]))
	nameOff := int(binary.LittleEndian.Uint16(buf[nameOffOff : nameOffOff+2]))
	if nameOff+nameLen <= recLen && nameOff+nameLen <= len(buf) {
		name = decodeUTF16(buf[nameOff : nameOff+nameLen])
	}
	return fileRef, parentRef, name, recLen
}

// getFileRecord pide a NTFS el registro MFT de fileRef y lo parsea. FSCTL puede
// devolver el registro en uso de ordinal <= al pedido; si el nº de entrada MFT
// devuelto no coincide, se descarta.
func getFileRecord(h windows.Handle, fileRef uint64) (Record, error) {
	in := make([]byte, 8)
	binary.LittleEndian.PutUint64(in, fileRef)
	// NTFS_FILE_RECORD_OUTPUT_BUFFER: FileReferenceNumber(8) + FileRecordLength(4)
	// + FileRecordBuffer(...). 8 KiB cubre registros de 1024 y 4096 bytes con holgura.
	out := make([]byte, 8192)
	var ret uint32
	err := windows.DeviceIoControl(h, fsctlGetNtfsFileRecord,
		&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
	if err != nil {
		return Record{}, fmt.Errorf("GET_NTFS_FILE_RECORD ref %d: %w", fileRef, err)
	}
	if ret < 12 {
		return Record{}, fmt.Errorf("respuesta MFT muy corta: %d", ret)
	}
	gotRef := binary.LittleEndian.Uint64(out[0:8])
	if gotRef&mftEntryMask != fileRef&mftEntryMask {
		return Record{}, errors.New("FSCTL devolvió otro registro (el pedido no está en uso)")
	}
	recLen := int(binary.LittleEndian.Uint32(out[8:12]))
	if recLen <= 0 || 12+recLen > int(ret) {
		return Record{}, errors.New("FileRecordLength fuera de rango")
	}
	return parseRecord(out[12 : 12+recLen])
}
```

- [ ] **Step 5: Correr los tests y el build de Windows**

Run: `go test ./internal/winfs/mft/`
Expected: PASS (el test de integración hace SKIP si no hay elevación/FSCTL).
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./internal/winfs/mft/`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./internal/winfs/mft/`
Expected: sin advertencias.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/mft/mft_windows.go internal/winfs/mft/mft_other.go internal/winfs/mft/mft_windows_test.go
git commit -m "feat: scan de timestomping vía ENUM_USN_DATA + FSCTL_GET_NTFS_FILE_RECORD"
```

---

### Task 6: Colector MFT y registro en el entrypoint

**Files:**
- Create: `internal/collector/mft/mft.go`
- Test: `internal/collector/mft/mft_test.go`
- Modify: `internal/agent/live_windows.go` (registrar el colector)

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact`, `collector.PriorityDisk` (Fase 1); `mft.ScanTimestomp`, `mft.Finding` (Task 5).
- Produces:
  - `type Collector struct { Volume string }`
  - `func New() *Collector` — `Volume` default `\\.\C:`.
  - Implementa `Name() string` = `"mft_timestomp"`, `Priority() int` = `collector.PriorityDisk`, `Collect(ctx) ([]collector.Artifact, error)`.

- [ ] **Step 1: Escribir el test que falla**

```go
//go:build windows

// internal/collector/mft/mft_test.go
package mft

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "mft_timestomp" {
		t.Fatalf("Name = %q, want mft_timestomp", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta la
// forma del contrato (skip si el volumen no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("MFT no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "mft_timestomp" {
			t.Fatalf("Type = %q, want mft_timestomp", a.Type)
		}
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/mft/`
Expected: FAIL de compilación — `undefined: New`.

- [ ] **Step 3: Escribir `mft.go`**

```go
//go:build windows

// internal/collector/mft/mft.go
package mft

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
)

// Collector detecta timestomping en archivos forenses del volumen vía MFT.
type Collector struct {
	Volume string
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "mft_timestomp" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	findings, err := winmft.ScanTimestomp(ctx, c.Volume)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(findings))
	for _, f := range findings {
		b, _ := json.Marshal(f)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "mft_timestomp",
			Source:    f.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/mft/`
Expected: PASS (integración con SKIP si no hay volumen accesible).

- [ ] **Step 5: Registrar el colector en `live_windows.go`**

En `internal/agent/live_windows.go`, agregar al bloque de imports (junto a los otros colectores):
```go
	mftcol "github.com/telagem/agent-windows/internal/collector/mft"
```
Y agregar la instancia al slice `collectors`, después de `usncol.New()`:
```go
	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
	}
```

- [ ] **Step 6: Verificar build completo y todos los tests**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `go test ./...`
Expected: PASS (los tests de integración MFT/USN hacen SKIP si no hay elevación).

- [ ] **Step 7: Commit**

```bash
git add internal/collector/mft/ internal/agent/live_windows.go
git commit -m "feat: colector MFT timestomping registrado en el entrypoint live"
```

---

## Notas para la Fase 3B-2 (no implementar ahora)

- Primitiva `internal/winfs/ntfs`: acceso raw a `\\.\C:` con `SetFilePointer`/`ReadFile` alineado a sector, parseo del boot sector (`$Boot`) para localizar el `$MFT`, y decodificación de data runs de `$DATA` (residente y no-residente).
- Enumeración/recuperación de entradas borradas: registros MFT con `InUse = 0` que `ENUM_USN_DATA` no lista (el journal ya los rotó). Reutiliza `parseRecord` (Task 3), que ya expone el flag `InUse`.
- Resolución de ruta completa post-borrado desde el árbol de directorios del MFT (aunque el journal ya no lo tenga). Reutiliza `ntfspath.ResolvePath` (Task 2).
- Reutiliza `wintime.FiletimeToTime`, `fsforensic` y el patrón de build tags de este plan.
