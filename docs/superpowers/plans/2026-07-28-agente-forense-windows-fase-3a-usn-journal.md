# Agente Forense Windows — Fase 3A (Colector USN Journal) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agregar un colector que lea el USN Change Journal del volumen `C:` vía FSCTL y reporte eventos forensicamente relevantes (borrado, rename, creación, sobrescritura de ejecutables/scripts) con ruta completa, respetando el invariante de privacidad.

**Architecture:** El USN Journal se lee con `DeviceIoControl` (FSCTL) sobre un handle read-only de `\\.\C:`; no toca el MFT crudo (eso es Fase 3B). El parseo de records, la resolución de rutas y el filtrado son funciones puras (testeables en cualquier host); solo `usn_windows.go` toca syscalls. Se extrae primero un helper compartido `wintime.FiletimeToTime` hoy duplicado.

**Tech Stack:** Go 1.22+, `golang.org/x/sys/windows` (DeviceIoControl, CreateFile), stdlib (`encoding/binary`, `unicode/utf16`, `path/filepath`). Sin CGO, sin dependencias externas en runtime.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Go 1.22+ como mínimo. Module path: `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime (stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` INFO (el `runner` recupera panics y propaga errores).
- Nunca recolectar contenido ni nombres de archivos personales: solo metadatos forenses (rutas de ejecutables/scripts, timestamps, razones).
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

---

### Task 1: Helper compartido `wintime.FiletimeToTime` + refactor de colectores

**Files:**
- Create: `internal/winfs/wintime/wintime.go`
- Test: `internal/winfs/wintime/wintime_test.go`
- Modify: `internal/collector/prefetch/parse.go` (elimina `filetimeToTime` local, usa el helper)
- Modify: `internal/collector/shimcache/parse.go` (idem)
- Modify: `internal/collector/bam/bam.go` (idem, preservando el bool `ok`)

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func FiletimeToTime(ft uint64) time.Time` — 100ns desde 1601-01-01 UTC a `time.Time` UTC; `ft == 0` devuelve `time.Time{}`.

**Nota:** `amcache` NO se toca: usa `parseLinkDate` (formato string `MM/DD/YYYY HH:MM:SS`), no una conversión FILETIME.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/wintime/wintime_test.go
package wintime

import (
	"testing"
	"time"
)

func TestFiletimeToTimeKnownValue(t *testing.T) {
	// 0x01D9553EC1174000 = 2023-03-13T00:00:00Z (FILETIME, 100ns desde 1601).
	got := FiletimeToTime(0x01D9553EC1174000)
	want := time.Date(2023, 3, 13, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("FiletimeToTime = %s, want %s", got, want)
	}
}

func TestFiletimeToTimeZeroIsZeroTime(t *testing.T) {
	if got := FiletimeToTime(0); !got.IsZero() {
		t.Fatalf("FiletimeToTime(0) = %s, want cero", got)
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/wintime/`
Expected: FAIL de compilación — `undefined: FiletimeToTime`.

- [ ] **Step 3: Escribir `wintime.go`**

```go
// internal/winfs/wintime/wintime.go
package wintime

import "time"

// FiletimeToTime convierte un FILETIME de Windows (intervalos de 100ns desde
// 1601-01-01 UTC) a time.Time UTC. Un valor cero devuelve time.Time{} (cero).
func FiletimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600 // segundos entre 1601 y 1970
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}
```

- [ ] **Step 4: Correr el test para verificar que pasa**

Run: `go test ./internal/winfs/wintime/`
Expected: PASS.

- [ ] **Step 5: Refactorizar `prefetch/parse.go`**

Eliminar la función `filetimeToTime` local (el bloque completo `func filetimeToTime(ft uint64) time.Time { ... }`) y reemplazar su única llamada. Añadir el import.

En el bloque de imports de `internal/collector/prefetch/parse.go`, agregar:
```go
	"github.com/telagem/agent-windows/internal/winfs/wintime"
```
Reemplazar la llamada `e.LastRunTimes = append(e.LastRunTimes, filetimeToTime(ft))` por:
```go
		e.LastRunTimes = append(e.LastRunTimes, wintime.FiletimeToTime(ft))
```
Borrar la definición local de `filetimeToTime`.

- [ ] **Step 6: Refactorizar `shimcache/parse.go`**

En `internal/collector/shimcache/parse.go`, agregar al import:
```go
	"github.com/telagem/agent-windows/internal/winfs/wintime"
```
Reemplazar la llamada dentro de `parseWin10Record`:
```go
	return Entry{Path: path, ModifiedTime: wintime.FiletimeToTime(ft)}, nil
```
Borrar la definición local `func filetimeToTime(ft uint64) time.Time { ... }`.

- [ ] **Step 7: Refactorizar `bam/bam.go` (preservando el bool `ok`)**

En `internal/collector/bam/bam.go`, agregar al import:
```go
	"github.com/telagem/agent-windows/internal/winfs/wintime"
```
Reemplazar el cuerpo de `decodeBAMValue` por:
```go
// decodeBAMValue extrae el FILETIME de los primeros 8 bytes del valor BAM.
func decodeBAMValue(raw []byte) (time.Time, bool) {
	if len(raw) < 8 {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(raw[:8])
	if ft == 0 {
		return time.Time{}, false
	}
	return wintime.FiletimeToTime(ft), true
}
```
Si tras esto `encoding/binary` sigue usándose (sí, para `Uint64`), dejar el import; el import de `time` sigue usándose por la firma. Verificar con `go build`.

- [ ] **Step 8: Correr los tests de los tres colectores refactorizados**

Run: `go test ./internal/collector/prefetch/ ./internal/collector/shimcache/ ./internal/collector/bam/ ./internal/winfs/wintime/`
Expected: PASS (todos). Los colectores mantienen su comportamiento; solo cambió de dónde viene la conversión.

- [ ] **Step 9: Commit**

```bash
git add internal/winfs/wintime/ internal/collector/prefetch/parse.go internal/collector/shimcache/parse.go internal/collector/bam/bam.go
git commit -m "refactor: extraer wintime.FiletimeToTime compartido (DRY)"
```

---

### Task 2: Parseo puro de records USN (`record.go`)

**Files:**
- Create: `internal/winfs/usn/record.go`
- Test: `internal/winfs/usn/record_test.go`

**Interfaces:**
- Consumes: `wintime.FiletimeToTime` (Task 1).
- Produces:
  - `type Record struct { USN int64; FileRef uint64; ParentRef uint64; Reason uint32; Timestamp time.Time; FileName string }`
  - `func parseRecord(buf []byte) (Record, int, error)` — parsea un `USN_RECORD_V2` (o V3) desde el inicio de `buf`; devuelve el record, `RecordLength` (bytes consumidos, para avanzar al siguiente) y error. En versión desconocida devuelve error pero con el `RecordLength` correcto para poder saltear.
  - Constantes de razones: `ReasonDataOverwrite = 0x00000001`, `ReasonDataTruncation = 0x00000004`, `ReasonFileCreate = 0x00000100`, `ReasonFileDelete = 0x00000200`, `ReasonRenameOldName = 0x00001000`, `ReasonRenameNewName = 0x00002000`.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/usn/record_test.go
package usn

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildV2 construye un USN_RECORD_V2 sintético para testeo.
func buildV2(fileRef, parentRef uint64, usn int64, ft uint64, reason uint32, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], c)
	}
	const fixed = 0x3C // 60 bytes de header fijo V2
	recLen := fixed + len(nameBytes)
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(buf[4:6], 2) // MajorVersion
	binary.LittleEndian.PutUint64(buf[0x08:0x10], fileRef)
	binary.LittleEndian.PutUint64(buf[0x10:0x18], parentRef)
	binary.LittleEndian.PutUint64(buf[0x18:0x20], uint64(usn))
	binary.LittleEndian.PutUint64(buf[0x20:0x28], ft)
	binary.LittleEndian.PutUint32(buf[0x28:0x2C], reason)
	binary.LittleEndian.PutUint16(buf[0x38:0x3A], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(buf[0x3A:0x3C], fixed)
	copy(buf[fixed:], nameBytes)
	return buf
}

func TestParseRecordV2(t *testing.T) {
	buf := buildV2(0x1122, 0x3344, 42, 0x01D9553EC1174000, ReasonFileDelete, "cheat.exe")
	rec, n, err := parseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord error: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("RecordLength = %d, want %d", n, len(buf))
	}
	if rec.FileName != "cheat.exe" {
		t.Fatalf("FileName = %q", rec.FileName)
	}
	if rec.FileRef != 0x1122 || rec.ParentRef != 0x3344 {
		t.Fatalf("refs = %x/%x", rec.FileRef, rec.ParentRef)
	}
	if rec.Reason&ReasonFileDelete == 0 {
		t.Fatalf("Reason = %x, sin ReasonFileDelete", rec.Reason)
	}
	if rec.Timestamp.IsZero() {
		t.Fatal("Timestamp no debería ser cero")
	}
}

func TestParseRecordTruncated(t *testing.T) {
	if _, _, err := parseRecord([]byte{0x01, 0x02}); err == nil {
		t.Fatal("esperaba error con buffer truncado")
	}
}

func TestParseRecordUnknownVersionReturnsLength(t *testing.T) {
	buf := buildV2(1, 2, 3, 0, ReasonFileCreate, "x.exe")
	binary.LittleEndian.PutUint16(buf[4:6], 9) // versión inexistente
	_, n, err := parseRecord(buf)
	if err == nil {
		t.Fatal("esperaba error con versión desconocida")
	}
	if n != len(buf) {
		t.Fatalf("RecordLength = %d, want %d (para poder saltear)", n, len(buf))
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/usn/`
Expected: FAIL de compilación — `undefined: parseRecord`, `undefined: ReasonFileDelete`, etc.

- [ ] **Step 3: Escribir `record.go`**

```go
// internal/winfs/usn/record.go
package usn

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Razones USN relevantes (winioctl.h).
const (
	ReasonDataOverwrite  = 0x00000001
	ReasonDataTruncation = 0x00000004
	ReasonFileCreate     = 0x00000100
	ReasonFileDelete     = 0x00000200
	ReasonRenameOldName  = 0x00001000
	ReasonRenameNewName  = 0x00002000
)

// Record es un evento del USN Change Journal ya parseado.
type Record struct {
	USN       int64
	FileRef   uint64
	ParentRef uint64
	Reason    uint32
	Timestamp time.Time
	FileName  string
}

// parseRecord parsea un USN_RECORD_V2 o V3 desde el inicio de buf. Devuelve el
// record, cuántos bytes ocupa (RecordLength, para avanzar) y error. En versión
// desconocida devuelve error PERO con el RecordLength correcto, para que el
// llamador pueda saltear el record y continuar.
func parseRecord(buf []byte) (Record, int, error) {
	if len(buf) < 4 {
		return Record{}, 0, fmt.Errorf("buffer USN truncado: %d bytes", len(buf))
	}
	recLen := int(binary.LittleEndian.Uint32(buf[0:4]))
	if recLen < 8 || recLen > len(buf) {
		return Record{}, 0, fmt.Errorf("RecordLength inválido: %d", recLen)
	}
	major := binary.LittleEndian.Uint16(buf[4:6])
	switch major {
	case 2:
		return parseV2(buf, recLen)
	case 3:
		return parseV3(buf, recLen)
	default:
		return Record{}, recLen, fmt.Errorf("versión de record USN no soportada: %d", major)
	}
}

// parseV2 parsea el layout de 60 bytes de header + nombre UTF-16.
func parseV2(buf []byte, recLen int) (Record, int, error) {
	const fixed = 0x3C // 60
	if recLen < fixed {
		return Record{}, recLen, fmt.Errorf("record V2 más corto que el header")
	}
	nameLen := int(binary.LittleEndian.Uint16(buf[0x38:0x3A]))
	nameOff := int(binary.LittleEndian.Uint16(buf[0x3A:0x3C]))
	if nameOff+nameLen > recLen || nameOff+nameLen > len(buf) {
		return Record{}, recLen, fmt.Errorf("nombre fuera de rango en record V2")
	}
	rec := Record{
		FileRef:   binary.LittleEndian.Uint64(buf[0x08:0x10]),
		ParentRef: binary.LittleEndian.Uint64(buf[0x10:0x18]),
		USN:       int64(binary.LittleEndian.Uint64(buf[0x18:0x20])),
		Timestamp: wintime.FiletimeToTime(binary.LittleEndian.Uint64(buf[0x20:0x28])),
		Reason:    binary.LittleEndian.Uint32(buf[0x28:0x2C]),
		FileName:  decodeUTF16(buf[nameOff : nameOff+nameLen]),
	}
	return rec, recLen, nil
}

// parseV3 parsea el layout con FILE_ID_128 (16 bytes por referencia). Los refs
// se truncan a los 64 bits bajos, que en NTFS son el nº de entrada MFT + secuencia.
func parseV3(buf []byte, recLen int) (Record, int, error) {
	const fixed = 0x4C // 76
	if recLen < fixed {
		return Record{}, recLen, fmt.Errorf("record V3 más corto que el header")
	}
	nameLen := int(binary.LittleEndian.Uint16(buf[0x48:0x4A]))
	nameOff := int(binary.LittleEndian.Uint16(buf[0x4A:0x4C]))
	if nameOff+nameLen > recLen || nameOff+nameLen > len(buf) {
		return Record{}, recLen, fmt.Errorf("nombre fuera de rango en record V3")
	}
	rec := Record{
		FileRef:   binary.LittleEndian.Uint64(buf[0x08:0x10]), // low 64 de FILE_ID_128
		ParentRef: binary.LittleEndian.Uint64(buf[0x18:0x20]),
		USN:       int64(binary.LittleEndian.Uint64(buf[0x28:0x30])),
		Timestamp: wintime.FiletimeToTime(binary.LittleEndian.Uint64(buf[0x30:0x38])),
		Reason:    binary.LittleEndian.Uint32(buf[0x38:0x3C]),
		FileName:  decodeUTF16(buf[nameOff : nameOff+nameLen]),
	}
	return rec, recLen, nil
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

Run: `go test ./internal/winfs/usn/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/usn/record.go internal/winfs/usn/record_test.go
git commit -m "feat: parseo puro de records USN_RECORD_V2/V3"
```

---

### Task 3: Resolución de ruta desde el mapa de padres (`path.go`)

**Files:**
- Create: `internal/winfs/usn/path.go`
- Test: `internal/winfs/usn/path_test.go`

**Interfaces:**
- Consumes: nada (lógica pura).
- Produces:
  - `type ParentEntry struct { Name string; ParentRef uint64 }`
  - `func resolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string` — sube por `parentMap` desde `parentRef` construyendo la ruta absoluta (con `\` inicial); corta en la raíz del volumen; si un padre falta, antepone `<sin-resolver>`.
  - `const unresolvedPrefix = "<sin-resolver>"`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/usn/path_test.go
package usn

import "testing"

// rootRef simula el FileRef de la raíz del volumen (nº de entrada MFT 5).
const testRootRef = 0x0005000000000005

func TestResolvePathFull(t *testing.T) {
	pm := map[uint64]ParentEntry{
		100: {Name: "Users", ParentRef: testRootRef},
		200: {Name: "Downloads", ParentRef: 100},
	}
	got := resolvePath(pm, 200, "cheat.exe")
	want := `\Users\Downloads\cheat.exe`
	if got != want {
		t.Fatalf("resolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathMissingParent(t *testing.T) {
	got := resolvePath(map[uint64]ParentEntry{}, 999, "evil.exe")
	want := `\` + unresolvedPrefix + `\evil.exe`
	if got != want {
		t.Fatalf("resolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathAtRoot(t *testing.T) {
	got := resolvePath(map[uint64]ParentEntry{}, testRootRef, "pagefile.sys")
	if got != `\pagefile.sys` {
		t.Fatalf("resolvePath = %q, want %q", got, `\pagefile.sys`)
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/usn/ -run TestResolvePath`
Expected: FAIL de compilación — `undefined: resolvePath`, `undefined: ParentEntry`.

- [ ] **Step 3: Escribir `path.go`**

```go
// internal/winfs/usn/path.go
package usn

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

// resolvePath reconstruye la ruta absoluta subiendo por parentMap desde
// parentRef. Corta en la raíz; si un padre falta, antepone unresolvedPrefix.
func resolvePath(parentMap map[uint64]ParentEntry, parentRef uint64, leaf string) string {
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

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/usn/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/usn/path.go internal/winfs/usn/path_test.go
git commit -m "feat: resolución de ruta USN desde mapa de padres"
```

---

### Task 4: Filtrado forense (`filter.go`)

**Files:**
- Create: `internal/winfs/usn/filter.go`
- Test: `internal/winfs/usn/filter_test.go`

**Interfaces:**
- Consumes: constantes `Reason*` (Task 2).
- Produces:
  - `func hasForensicExtension(name string) bool`
  - `func isSuspiciousName(name string) bool`
  - `func reasonIsRelevant(reason uint32) bool`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/usn/filter_test.go
package usn

import "testing"

func TestHasForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"cheat.exe":        true,
		"driver.SYS":       true,
		"script.ps1":       true,
		"documento.docx":   false,
		"foto.jpg":         false,
		"sinextension":     false,
	}
	for name, want := range cases {
		if got := hasForensicExtension(name); got != want {
			t.Errorf("hasForensicExtension(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsSuspiciousName(t *testing.T) {
	if !isSuspiciousName("FreeFire_Injector.exe") {
		t.Error("esperaba sospechoso para nombre con 'inject'")
	}
	if isSuspiciousName("notepad.exe") {
		t.Error("notepad.exe no debería ser sospechoso")
	}
}

func TestReasonIsRelevant(t *testing.T) {
	if !reasonIsRelevant(ReasonFileDelete) {
		t.Error("FileDelete debería ser relevante")
	}
	if reasonIsRelevant(0x80000000) { // USN_REASON_CLOSE, no relevante por sí solo
		t.Error("CLOSE-solo no debería ser relevante")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/usn/ -run 'TestHasForensic|TestIsSuspicious|TestReasonIsRelevant'`
Expected: FAIL de compilación — `undefined: hasForensicExtension`, etc.

- [ ] **Step 3: Escribir `filter.go`**

```go
// internal/winfs/usn/filter.go
package usn

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

// relevantReasonMask agrega las razones USN forensicamente significativas.
const relevantReasonMask = ReasonDataOverwrite | ReasonDataTruncation |
	ReasonFileCreate | ReasonFileDelete | ReasonRenameOldName | ReasonRenameNewName

// hasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func hasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// isSuspiciousName reporta si el nombre contiene un marcador sospechoso.
func isSuspiciousName(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range suspiciousMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// reasonIsRelevant reporta si la máscara de razones incluye alguna relevante.
func reasonIsRelevant(reason uint32) bool {
	return reason&relevantReasonMask != 0
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/usn/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/usn/filter.go internal/winfs/usn/filter_test.go
git commit -m "feat: filtrado forense de eventos USN (extensión, patrón, razón)"
```

---

### Task 5: Lectura real del journal (`usn_windows.go` / `usn_other.go`)

**Files:**
- Create: `internal/winfs/usn/usn_windows.go`
- Create: `internal/winfs/usn/usn_other.go`
- Test: `internal/winfs/usn/usn_windows_test.go`

**Interfaces:**
- Consumes: `parseRecord`, `Record`, `ParentEntry`, `resolvePath`, `hasForensicExtension`, `isSuspiciousName`, `reasonIsRelevant` (Tasks 2-4).
- Produces:
  - `type Entry struct { Record; FullPath string; Suspicious bool }`
  - `var ErrUnsupported = errors.New("USN journal solo disponible en Windows")`
  - `func ReadJournal(ctx context.Context, volume string) ([]Entry, error)` — abre el volumen, construye el mapa de padres con `ENUM_USN_DATA`, lee el journal con `READ_USN_JOURNAL`, filtra y resuelve rutas. Fuera de Windows devuelve `ErrUnsupported`.

- [ ] **Step 1: Escribir el test (integración, con skip)**

```go
//go:build windows

// internal/winfs/usn/usn_windows_test.go
package usn

import (
	"context"
	"errors"
	"testing"
)

// TestReadJournalIntegration corre solo si hay acceso al journal (elevación).
// No es determinista: valida forma, no contenido.
func TestReadJournalIntegration(t *testing.T) {
	entries, err := ReadJournal(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("USN no accesible (¿sin elevación o journal inactivo?): %v", err)
	}
	for _, e := range entries {
		if e.FullPath == "" {
			t.Fatalf("entry sin FullPath: %+v", e)
		}
		if !hasForensicExtension(e.FileName) && !isSuspiciousName(e.FileName) {
			t.Fatalf("entry no pasó el filtro forense: %q", e.FileName)
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

Run: `go test ./internal/winfs/usn/`
Expected: FAIL de compilación — `undefined: ReadJournal`, `undefined: Entry`, `undefined: ErrUnsupported`.

- [ ] **Step 3: Escribir `usn_other.go` (stub no-Windows)**

```go
//go:build !windows

// internal/winfs/usn/usn_other.go
package usn

import (
	"context"
	"errors"
)

// ErrUnsupported se devuelve al intentar leer el journal fuera de Windows.
var ErrUnsupported = errors.New("USN journal solo disponible en Windows")

// Entry es un Record enriquecido con ruta completa y flag de sospecha.
type Entry struct {
	Record
	FullPath   string
	Suspicious bool
}

// ReadJournal no está soportado fuera de Windows.
func ReadJournal(ctx context.Context, volume string) ([]Entry, error) {
	return nil, ErrUnsupported
}
```

- [ ] **Step 4: Escribir `usn_windows.go` (FSCTL real)**

```go
//go:build windows

// internal/winfs/usn/usn_windows.go
package usn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows (no debería
// dispararse aquí).
var ErrUnsupported = errors.New("USN journal solo disponible en Windows")

// Entry es un Record enriquecido con ruta completa y flag de sospecha.
type Entry struct {
	Record
	FullPath   string
	Suspicious bool
}

// FSCTL codes (winioctl.h).
const (
	fsctlQueryUsnJournal = 0x000900f4
	fsctlEnumUsnData     = 0x000900b3
	fsctlReadUsnJournal  = 0x000900bb
)

// ReadJournal abre el volumen, construye el mapa de padres y devuelve los
// eventos USN relevantes con ruta resuelta.
func ReadJournal(ctx context.Context, volume string) ([]Entry, error) {
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

	journalID, err := queryJournal(h)
	if err != nil {
		return nil, err
	}
	parentMap, err := enumParents(ctx, h)
	if err != nil {
		return nil, err
	}
	return readRecords(ctx, h, journalID, parentMap)
}

// queryJournal devuelve el UsnJournalID (offset 0 del USN_JOURNAL_DATA_V0).
func queryJournal(h windows.Handle) (uint64, error) {
	out := make([]byte, 80)
	var ret uint32
	err := windows.DeviceIoControl(h, fsctlQueryUsnJournal,
		nil, 0, &out[0], uint32(len(out)), &ret, nil)
	if err != nil {
		return 0, fmt.Errorf("QUERY_USN_JOURNAL (¿journal inactivo?): %w", err)
	}
	return binary.LittleEndian.Uint64(out[0:8]), nil
}

// enumParents recorre ENUM_USN_DATA acumulando FileRef -> {nombre, padre}.
func enumParents(ctx context.Context, h windows.Handle) (map[uint64]ParentEntry, error) {
	parentMap := make(map[uint64]ParentEntry)
	// MFT_ENUM_DATA_V0: StartFileReferenceNumber(8) + LowUsn(8) + HighUsn(8).
	in := make([]byte, 24)
	binary.LittleEndian.PutUint64(in[8:16], 0)                    // LowUsn
	binary.LittleEndian.PutUint64(in[16:24], 0xFFFFFFFFFFFFFFFF)  // HighUsn
	out := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return parentMap, ctx.Err()
		default:
		}
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlEnumUsnData,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			// ERROR_HANDLE_EOF marca el fin de la enumeración.
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return parentMap, fmt.Errorf("ENUM_USN_DATA: %w", err)
		}
		if ret <= 8 {
			break
		}
		// Los primeros 8 bytes son el próximo StartFileReferenceNumber.
		next := binary.LittleEndian.Uint64(out[0:8])
		pos := 8
		for pos < int(ret) {
			rec, n, perr := parseRecord(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			if perr == nil {
				parentMap[rec.FileRef] = ParentEntry{Name: rec.FileName, ParentRef: rec.ParentRef}
			}
			pos += n
		}
		binary.LittleEndian.PutUint64(in[0:8], next)
	}
	return parentMap, nil
}

// readRecords lee el journal desde el inicio y filtra/resuelve los relevantes.
func readRecords(ctx context.Context, h windows.Handle, journalID uint64, parentMap map[uint64]ParentEntry) ([]Entry, error) {
	// READ_USN_JOURNAL_DATA_V0: StartUsn(8) + ReasonMask(4) + ReturnOnlyOnClose(4)
	// + Timeout(8) + BytesToWaitFor(8) + UsnJournalID(8) = 40 bytes.
	in := make([]byte, 40)
	binary.LittleEndian.PutUint32(in[8:12], relevantReasonMask) // ReasonMask
	binary.LittleEndian.PutUint64(in[32:40], journalID)
	out := make([]byte, 64*1024)

	var entries []Entry
	var startUsn int64
	for {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}
		binary.LittleEndian.PutUint64(in[0:8], uint64(startUsn))
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlReadUsnJournal,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			return entries, fmt.Errorf("READ_USN_JOURNAL: %w", err)
		}
		if ret <= 8 {
			break // sin más records
		}
		nextUsn := int64(binary.LittleEndian.Uint64(out[0:8]))
		pos := 8
		for pos < int(ret) {
			rec, n, perr := parseRecord(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			pos += n
			if perr != nil {
				continue
			}
			if !reasonIsRelevant(rec.Reason) {
				continue
			}
			if !hasForensicExtension(rec.FileName) && !isSuspiciousName(rec.FileName) {
				continue
			}
			entries = append(entries, Entry{
				Record:     rec,
				FullPath:   resolvePath(parentMap, rec.ParentRef, rec.FileName),
				Suspicious: isSuspiciousName(rec.FileName),
			})
		}
		if nextUsn == startUsn {
			break
		}
		startUsn = nextUsn
	}
	return entries, nil
}
```

- [ ] **Step 5: Correr los tests y el build de Windows**

Run: `go test ./internal/winfs/usn/`
Expected: PASS (el test de integración hace SKIP si no hay elevación/journal).
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./internal/winfs/usn/`
Expected: compila sin errores.
Run: `go vet ./internal/winfs/usn/`
Expected: sin advertencias.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/usn/usn_windows.go internal/winfs/usn/usn_other.go internal/winfs/usn/usn_windows_test.go
git commit -m "feat: lectura del USN journal vía FSCTL (query/enum/read) con filtrado"
```

---

### Task 6: Colector USN y registro en el entrypoint

**Files:**
- Create: `internal/collector/usn/usn.go`
- Test: `internal/collector/usn/usn_test.go`
- Modify: `internal/agent/live_windows.go` (registrar el colector)

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact`, `collector.PriorityDisk` (Fase 1); `usn.ReadJournal`, `usn.Entry` (Task 5).
- Produces:
  - `type Collector struct { Volume string }`
  - `func New() *Collector` — `Volume` default `\\.\C:`.
  - Implementa `Name() string` = `"usn"`, `Priority() int` = `collector.PriorityDisk`, `Collect(ctx) ([]collector.Artifact, error)`.

- [ ] **Step 1: Escribir el test que falla**

```go
//go:build windows

// internal/collector/usn/usn_test.go
package usn

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "usn" {
		t.Fatalf("Name = %q, want usn", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta
// la forma del contrato (skip si el journal no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("USN no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "usn" {
			t.Fatalf("Type = %q, want usn", a.Type)
		}
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/usn/`
Expected: FAIL de compilación — `undefined: New`.

- [ ] **Step 3: Escribir `usn.go`**

```go
//go:build windows

// internal/collector/usn/usn.go
package usn

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	winusn "github.com/telagem/agent-windows/internal/winfs/usn"
)

// Collector lee eventos relevantes del USN Change Journal del volumen.
type Collector struct {
	Volume string
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "usn" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	entries, err := winusn.ReadJournal(ctx, c.Volume)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "usn",
			Source:    e.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/usn/`
Expected: PASS (integración con SKIP si no hay journal accesible).

- [ ] **Step 5: Registrar el colector en `live_windows.go`**

En `internal/agent/live_windows.go`, agregar al bloque de imports (orden alfabético entre los colectores):
```go
	usncol "github.com/telagem/agent-windows/internal/collector/usn"
```
Y agregar la instancia al slice `collectors`, después de `prefetch.New()`:
```go
	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
	}
```

- [ ] **Step 6: Verificar build completo y todos los tests**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `go test ./...`
Expected: PASS (los tests de integración USN hacen SKIP si no hay elevación).

- [ ] **Step 7: Commit**

```bash
git add internal/collector/usn/ internal/agent/live_windows.go
git commit -m "feat: colector USN journal registrado en el entrypoint live"
```

---

## Notas para la Fase 3B (no implementar ahora)

- Primitiva `internal/winfs/ntfs`: acceso raw a `\\.\C:` con `SetFilePointer`/`ReadFile` alineado a sector, parseo del boot sector (`$Boot`) para localizar el `$MFT`, y de registros MFT (`$STANDARD_INFORMATION`, `$FILE_NAME`, runs de `$DATA`).
- Detección de *timestomping*: comparar los 4 timestamps de `$STANDARD_INFORMATION` vs `$FILE_NAME` (una diferencia sospechosa delata manipulación con herramientas como `timestomp`).
- Recuperación de entradas borradas que el journal ya rotó (flag `InUse` del registro MFT en 0).
- Resolución de ruta completa post-borrado (el MFT tiene el árbol de directorios aunque el journal ya no).
- Reutiliza `wintime.FiletimeToTime` (Task 1) y el patrón de build tags de este plan.
