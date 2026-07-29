# Agente Forense Windows — Fase 3C: Persistencia (Servicios + Tareas Programadas) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detectar drivers no estándar instalados como servicio, tareas programadas ocultas o
sospechosas, y desincronización entre el XML de una tarea en disco y su entrada espejo en
`TaskCache\Tree` (evidencia de manipulación activa para ocultar rastros).

**Architecture:** Dos paquetes puros nuevos (`winfs/services`, `winfs/scheduler`) parsean
subárboles de registro (vía `reghive`, ya existente) y XML de tareas; un helper puro nuevo
(`winfs/wintext`) unifica la decodificación UTF-16 terminada en nulo, hoy duplicada en tres
colectores. Dos colectores delgados (`collector/services`, `collector/scheduler`) adaptan esas
primitivas al contrato `collector.Collector`. Un paquete de soporte de test (`reghive/reghivetest`)
arma hives `regf` sintéticos en memoria para que los tests de ambos paquetes de dominio corran de
verdad en cualquier host, sin depender de un dump real de registro.

**Tech Stack:** Go 1.25+, stdlib (`encoding/xml`, `encoding/binary`, `encoding/json`,
`path/filepath`, `io/fs`, `os`), sin CGO, sin dependencias externas en runtime.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Go 1.25+ (go.mod declara `go 1.25.0`). Module path: `github.com/telagem/agent-windows`.
- Sin dependencias externas en runtime (stdlib + `golang.org/x/sys` donde ya se usa). Ninguna
  tarea de este plan necesita `golang.org/x/sys` — todo es stdlib puro.
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` INFO.
- Nunca recolectar contenido de archivos personales, credenciales, historial ni mensajes: solo
  metadatos forenses.
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Ningún paquete nuevo lleva build tag `windows` (ni sus tests): todo es `reghive` puro + stdlib
  de archivos, corren en cualquier host. Solo `internal/agent/live_windows.go` (ya con su tag)
  registra los colectores.

## Estructura de archivos

- `internal/winfs/wintext/wintext.go` — helper puro: `DecodeUTF16`.
- `internal/collector/shimcache/parse.go`, `internal/collector/amcache/amcache.go`,
  `internal/collector/prefetch/parse.go` — (modificar) migrar a `wintext.DecodeUTF16`.
- `internal/winfs/reghive/reghivetest/builder.go` — soporte de test: arma hives `regf` sintéticos.
- `internal/winfs/services/services.go` — parseo puro del subárbol Services + heurística driver.
- `internal/winfs/scheduler/taskxml.go` — parseo puro de XML de tarea.
- `internal/winfs/scheduler/taskcache.go` — parseo puro de `TaskCache\Tree`.
- `internal/winfs/scheduler/diff.go` — cross-check XML↔TaskCache.
- `internal/collector/services/services.go` — adaptador `collector.Collector`.
- `internal/collector/scheduler/scheduler.go` — adaptador `collector.Collector`.
- `internal/agent/live_windows.go` — (modificar) registrar ambos colectores + hive SOFTWARE.

---

### Task 1: Extraer `wintext.DecodeUTF16` y migrar sus tres consumidores actuales

**Files:**
- Create: `internal/winfs/wintext/wintext.go`
- Test: `internal/winfs/wintext/wintext_test.go`
- Modify: `internal/collector/shimcache/parse.go`
- Modify: `internal/collector/amcache/amcache.go`
- Modify: `internal/collector/prefetch/parse.go`

**Interfaces:**
- Consumes: nada nuevo.
- Produces: `func wintext.DecodeUTF16(b []byte) string` — decodifica UTF-16LE, corta en el
  primer `\x00\x00` o al agotar el buffer.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/wintext/wintext_test.go
package wintext

import "testing"

func TestDecodeUTF16StopsAtNull(t *testing.T) {
	// "AB" en UTF-16LE seguido de terminador nulo y basura tras el terminador.
	b := []byte{'A', 0x00, 'B', 0x00, 0x00, 0x00, 'X', 0x00}
	got := DecodeUTF16(b)
	if got != "AB" {
		t.Fatalf("DecodeUTF16 = %q, want %q", got, "AB")
	}
}

func TestDecodeUTF16NoTerminator(t *testing.T) {
	// Sin terminador nulo: decodifica todo el buffer.
	b := []byte{'H', 0x00, 'I', 0x00}
	got := DecodeUTF16(b)
	if got != "HI" {
		t.Fatalf("DecodeUTF16 = %q, want %q", got, "HI")
	}
}

func TestDecodeUTF16Empty(t *testing.T) {
	if got := DecodeUTF16(nil); got != "" {
		t.Fatalf("DecodeUTF16(nil) = %q, want empty", got)
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/wintext/`
Expected: FAIL de compilación — `undefined: DecodeUTF16`.

- [ ] **Step 3: Escribir `wintext.go`**

```go
// internal/winfs/wintext/wintext.go
package wintext

import "encoding/binary"

// DecodeUTF16 decodifica una cadena UTF-16LE terminada en \x00\x00, o hasta
// agotar el buffer si no hay terminador. Usado para valores de registro
// REG_SZ/REG_EXPAND_SZ y para contenido XML tras remover el BOM.
func DecodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}
```

- [ ] **Step 4: Correr el test para verificar que pasa**

Run: `go test ./internal/winfs/wintext/`
Expected: PASS.

- [ ] **Step 5: Migrar `shimcache/parse.go`**

Agregar el import (junto a los existentes):
```go
	"github.com/telagem/agent-windows/internal/winfs/wintext"
```
Reemplazar el call site:
```go
	path := decodeUTF16(rec[2 : 2+pathLen])
```
por:
```go
	path := wintext.DecodeUTF16(rec[2 : 2+pathLen])
```
Eliminar la función local completa al final del archivo:
```go
func decodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}
```
`encoding/binary` se sigue usando en el resto del archivo (otros `binary.LittleEndian.*`): el
import se queda igual.

- [ ] **Step 6: Migrar `amcache/amcache.go`**

Agregar el import:
```go
	"github.com/telagem/agent-windows/internal/winfs/wintext"
```
Reemplazar los tres call sites:
```go
			e.Path = decodeUTF16(p)
```
```go
			e.SHA1 = normalizeFileID(decodeUTF16(fid))
```
```go
			e.LinkDate = parseLinkDate(decodeUTF16(ld))
```
por `wintext.DecodeUTF16(...)` en cada uno. Eliminar la función local `decodeUTF16` al final del
archivo (idéntica a la de shimcache). **Eliminar también el import `"encoding/binary"`**: en este
archivo solo lo usaba `decodeUTF16`; sin esa función queda sin uso y el build fallaría con
"imported and not used".

- [ ] **Step 7: Migrar `prefetch/parse.go`**

Agregar el import:
```go
	"github.com/telagem/agent-windows/internal/winfs/wintext"
```
Reemplazar el call site:
```go
	name := decodeUTF16(data[0x10:0x4C])
```
por:
```go
	name := wintext.DecodeUTF16(data[0x10:0x4C])
```
Eliminar la función local `decodeUTF16` al final del archivo (variante con `strings.Builder`, misma
semántica). **Eliminar también el import `"strings"`**: en este archivo solo lo usaba
`decodeUTF16`; sin esa función queda sin uso. `encoding/binary` se sigue usando en el resto del
archivo: se queda.

- [ ] **Step 8: Correr toda la suite y el build de Windows**

Run: `go test ./...`
Expected: PASS (mismos tests que antes, ahora usando el helper compartido).
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores (confirma que no quedó ningún import sin usar).

- [ ] **Step 9: Commit**

```bash
git add internal/winfs/wintext/ internal/collector/shimcache/parse.go internal/collector/amcache/amcache.go internal/collector/prefetch/parse.go
git commit -m "refactor: extraer wintext.DecodeUTF16 y migrar shimcache/amcache/prefetch"
```

---

### Task 2: Soporte de test — `reghivetest` (hives `regf` sintéticos)

**Files:**
- Create: `internal/winfs/reghive/reghivetest/builder.go`
- Test: `internal/winfs/reghive/reghivetest/builder_test.go`

**Interfaces:**
- Consumes: nada (opera sobre el mismo formato binario que `reghive.Open`/`Key`, sin importar
  ese paquete — construye bytes crudos que luego OTRO test alimenta a `reghive.Open`).
- Produces:
  - `type Builder struct{ ... }`
  - `func NewBuilder() *Builder`
  - `func (b *Builder) AddValue(name string, data []byte, regType uint32) uint32`
  - `func (b *Builder) AddKey(name string, subkeys []uint32, values []uint32) uint32`
  - `func (b *Builder) Build(rootOffset uint32) []byte`

Los tests de las Tareas 3 y 5 usan este builder para armar hives sintéticos en vez de depender de
un dump `.hve` real (que `reghive`/`bam` sí requieren hoy vía `testdata/*.hve` con `t.Skip` si
falta — un patrón más débil que no da cobertura real en un host sin ese fixture). Este builder da
tests deterministas que corren siempre.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/reghive/reghivetest/builder_test.go
package reghivetest

import (
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

func TestBuilderRoundTrip(t *testing.T) {
	b := NewBuilder()
	val := b.AddValue("Greeting", []byte("hi"), 1) // 2 bytes: camino inline
	child := b.AddKey("Child", nil, []uint32{val})
	root := b.AddKey("Root", []uint32{child}, nil)
	data := b.Build(root)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	rootKey, err := h.OpenKey("")
	if err != nil {
		t.Fatalf(`OpenKey(""): %v`, err)
	}
	if rootKey.Name() != "Root" {
		t.Fatalf("Name() = %q, want Root", rootKey.Name())
	}
	childKey, err := h.OpenKey("Child")
	if err != nil {
		t.Fatalf("OpenKey(Child): %v", err)
	}
	got, _, err := childKey.Value("Greeting")
	if err != nil {
		t.Fatalf("Value(Greeting): %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("Value = %q, want hi", string(got))
	}
}

func TestBuilderValueLongerThanFourBytes(t *testing.T) {
	b := NewBuilder()
	val := b.AddValue("Big", []byte("more than four bytes"), 1) // camino no-inline
	root := b.AddKey("Root", nil, []uint32{val})
	data := b.Build(root)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	rootKey, _ := h.OpenKey("")
	got, _, err := rootKey.Value("Big")
	if err != nil {
		t.Fatalf("Value(Big): %v", err)
	}
	if string(got) != "more than four bytes" {
		t.Fatalf("Value = %q", string(got))
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/reghive/reghivetest/`
Expected: FAIL de compilación — `undefined: NewBuilder`.

- [ ] **Step 3: Escribir `builder.go`**

```go
// internal/winfs/reghive/reghivetest/builder.go

// Package reghivetest arma hives regf sintéticos en memoria para testear
// paquetes que consumen reghive.Hive sin depender de un dump real de
// registro. Solo implementa lo que reghive.Open/Key realmente leen: no
// pretende ser un escritor de regf completo ni válido para regedit.
package reghivetest

import "encoding/binary"

// Builder arma un hive regf sintético celda por celda.
type Builder struct {
	cells []byte
}

// NewBuilder crea un builder vacío.
func NewBuilder() *Builder {
	return &Builder{}
}

// addCell agrega el contenido dado precedido por el prefijo de tamaño
// (negativo = celda asignada, como exige reghive.cellBody) y devuelve el
// offset de la celda.
func (b *Builder) addCell(body []byte) uint32 {
	offset := uint32(len(b.cells))
	size := int32(-(4 + len(body)))
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(size))
	b.cells = append(b.cells, header...)
	b.cells = append(b.cells, body...)
	return offset
}

// AddValue agrega una celda vk. Datos de hasta 4 bytes se guardan inline
// (igual que el formato real); más largos se guardan en una celda aparte.
func (b *Builder) AddValue(name string, data []byte, regType uint32) uint32 {
	const inlineFlag = 0x80000000
	var dataLen, dataOffset uint32
	if len(data) <= 4 {
		dataLen = inlineFlag | uint32(len(data))
		var inline [4]byte
		copy(inline[:], data)
		dataOffset = binary.LittleEndian.Uint32(inline[:])
	} else {
		dataLen = uint32(len(data))
		dataOffset = b.addCell(data)
	}
	vk := make([]byte, 20+len(name))
	copy(vk[0:2], "vk")
	binary.LittleEndian.PutUint16(vk[2:4], uint16(len(name)))
	binary.LittleEndian.PutUint32(vk[4:8], dataLen)
	binary.LittleEndian.PutUint32(vk[8:12], dataOffset)
	binary.LittleEndian.PutUint32(vk[12:16], regType)
	copy(vk[20:], name)
	return b.addCell(vk)
}

// AddKey agrega una celda nk con el nombre dado, offsets de subclaves (otras
// celdas nk, obtenidas de llamadas previas a AddKey) y offsets de valores
// (celdas vk, de AddValue), y devuelve su offset. Debe llamarse de abajo
// hacia arriba: primero los hijos, después el padre que los referencia.
func (b *Builder) AddKey(name string, subkeys []uint32, values []uint32) uint32 {
	var subkeyListOffset uint32
	if len(subkeys) > 0 {
		list := make([]byte, 4+len(subkeys)*8)
		copy(list[0:2], "lh")
		binary.LittleEndian.PutUint16(list[2:4], uint16(len(subkeys)))
		for i, off := range subkeys {
			base := 4 + i*8
			binary.LittleEndian.PutUint32(list[base:base+4], off)
			// hash (4 bytes siguientes) no se valida en esta implementación: cero.
		}
		subkeyListOffset = b.addCell(list)
	}
	var valueListOffset uint32
	if len(values) > 0 {
		list := make([]byte, len(values)*4)
		for i, off := range values {
			binary.LittleEndian.PutUint32(list[i*4:i*4+4], off)
		}
		valueListOffset = b.addCell(list)
	}
	nk := make([]byte, 76+len(name))
	copy(nk[0:2], "nk")
	binary.LittleEndian.PutUint32(nk[20:24], uint32(len(subkeys)))
	binary.LittleEndian.PutUint32(nk[28:32], subkeyListOffset)
	binary.LittleEndian.PutUint32(nk[36:40], uint32(len(values)))
	binary.LittleEndian.PutUint32(nk[40:44], valueListOffset)
	binary.LittleEndian.PutUint16(nk[72:74], uint16(len(name)))
	copy(nk[76:], name)
	return b.addCell(nk)
}

// Build ensambla el hive completo: base block (4096 bytes con la firma
// "regf" y el offset de la celda raíz) seguido de la región de celdas.
func (b *Builder) Build(rootOffset uint32) []byte {
	base := make([]byte, 4096)
	copy(base[0:4], "regf")
	binary.LittleEndian.PutUint32(base[36:40], rootOffset)
	return append(base, b.cells...)
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/reghive/reghivetest/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/reghive/reghivetest/
git commit -m "test: builder de hives regf sintéticos para tests de registro"
```

---

### Task 3: Parseo puro de Servicios (`internal/winfs/services`)

**Files:**
- Create: `internal/winfs/services/services.go`
- Test: `internal/winfs/services/services_test.go`

**Interfaces:**
- Consumes: `reghive.Key`, `reghive.Open` (Fase 1-2); `wintext.DecodeUTF16` (Task 1);
  `reghivetest.Builder` (Task 2, solo en el test).
- Produces:
  - `type DriverService struct { Name, ImagePath string; Type, Start uint32 }`
  - `func ParseServices(servicesKey *reghive.Key) ([]DriverService, error)`
  - `func IsNonMicrosoftDriver(s DriverService) bool`

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/services/services_test.go
package services

import (
	"encoding/binary"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/reghive/reghivetest"
)

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func utf16(s string) []byte {
	b := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func buildServicesHive(t *testing.T) *reghive.Hive {
	t.Helper()
	b := reghivetest.NewBuilder()

	// Servicio 1: driver kernel legítimo en System32\drivers.
	v1Type := b.AddValue("Type", u32(1), 4)
	v1Path := b.AddValue("ImagePath", utf16(`\SystemRoot\System32\drivers\afd.sys`), 2)
	svc1 := b.AddKey("Afd", nil, []uint32{v1Type, v1Path})

	// Servicio 2: driver kernel sospechoso, fuera de System32\drivers.
	v2Type := b.AddValue("Type", u32(1), 4)
	v2Path := b.AddValue("ImagePath", utf16(`C:\Users\Player\AppData\Local\Temp\evil.sys`), 2)
	svc2 := b.AddKey("EvilDrv", nil, []uint32{v2Type, v2Path})

	// Servicio 3: Win32 normal (no driver); no debe pasar el filtro aunque el path sea raro.
	v3Type := b.AddValue("Type", u32(0x10), 4)
	v3Path := b.AddValue("ImagePath", utf16(`C:\Temp\raro.exe`), 2)
	svc3 := b.AddKey("RandomSvc", nil, []uint32{v3Type, v3Path})

	// Servicio 4: malformado, sin Type. Debe omitirse sin abortar el resto.
	v4Path := b.AddValue("ImagePath", utf16(`C:\Temp\sin-type.sys`), 2)
	svc4 := b.AddKey("NoType", nil, []uint32{v4Path})

	servicesKey := b.AddKey("Services", []uint32{svc1, svc2, svc3, svc4}, nil)
	data := b.Build(servicesKey)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	return h
}

func TestParseServices(t *testing.T) {
	h := buildServicesHive(t)
	key, err := h.OpenKey("")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	got, err := ParseServices(key)
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	// 4 subclaves; NoType se omite por Type ausente -> 3 servicios válidos.
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3: %+v", len(got), got)
	}
}

func TestIsNonMicrosoftDriver(t *testing.T) {
	cases := []struct {
		name string
		svc  DriverService
		want bool
	}{
		{"kernel driver en System32", DriverService{Type: 1, ImagePath: `\SystemRoot\System32\drivers\afd.sys`}, false},
		{"kernel driver en Temp", DriverService{Type: 1, ImagePath: `C:\Users\Player\AppData\Local\Temp\evil.sys`}, true},
		{"filesystem driver en System32", DriverService{Type: 2, ImagePath: `system32\drivers\netbt.sys`}, false},
		{"Win32 own process fuera de System32", DriverService{Type: 0x10, ImagePath: `C:\Temp\raro.exe`}, false},
		{"prefijo NT device path", DriverService{Type: 1, ImagePath: `\??\C:\Temp\evil.sys`}, true},
	}
	for _, c := range cases {
		if got := IsNonMicrosoftDriver(c.svc); got != c.want {
			t.Errorf("%s: IsNonMicrosoftDriver = %v, want %v", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/services/`
Expected: FAIL de compilación — `undefined: ParseServices`, `undefined: DriverService`,
`undefined: IsNonMicrosoftDriver`.

- [ ] **Step 3: Escribir `services.go`**

```go
// internal/winfs/services/services.go
package services

import (
	"encoding/binary"
	"strings"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// DriverService es un servicio del registro con sus metadatos crudos.
type DriverService struct {
	Name      string
	ImagePath string
	Type      uint32 // REG_DWORD: 1=kernel driver, 2=filesystem driver, ...
	Start     uint32 // REG_DWORD: 0=Boot..4=Disabled
}

// Valores de Type relevantes (winnt.h). Cualquier otro valor (Win32
// own/share process, etc.) nunca es un driver.
const (
	serviceKernelDriver     = 0x1
	serviceFileSystemDriver = 0x2
)

// ParseServices recorre las subclaves de la clave "Services"
// (SYSTEM\CurrentControlSet\Services) y decodifica Name/ImagePath/Type/Start
// de cada una. Una subclave con Type o ImagePath faltante o malformado se
// omite; no aborta el resto.
func ParseServices(servicesKey *reghive.Key) ([]DriverService, error) {
	subs, err := servicesKey.Subkeys()
	if err != nil {
		return nil, err
	}
	var out []DriverService
	for _, s := range subs {
		vals, err := s.Values()
		if err != nil {
			continue
		}
		typeRaw, ok := vals["Type"]
		if !ok || len(typeRaw) < 4 {
			continue
		}
		imagePathRaw, ok := vals["ImagePath"]
		if !ok {
			continue
		}
		svc := DriverService{
			Name:      s.Name(),
			ImagePath: wintext.DecodeUTF16(imagePathRaw),
			Type:      binary.LittleEndian.Uint32(typeRaw[:4]),
		}
		if startRaw, ok := vals["Start"]; ok && len(startRaw) >= 4 {
			svc.Start = binary.LittleEndian.Uint32(startRaw[:4])
		}
		out = append(out, svc)
	}
	return out, nil
}

// IsNonMicrosoftDriver reporta si el servicio es driver (Type kernel o
// filesystem) cuyo ImagePath normalizado no cae bajo
// %SystemRoot%\System32\drivers\. Es una heurística por RUTA, no por firma
// de editor: sin CGO ni dependencias externas no hay validación de
// Authenticode offline. Cubre tanto binarios de terceros como maliciosos que
// no siguen la convención de instalación de Windows.
func IsNonMicrosoftDriver(s DriverService) bool {
	if s.Type != serviceKernelDriver && s.Type != serviceFileSystemDriver {
		return false
	}
	return !strings.Contains(normalizeImagePath(s.ImagePath), `\windows\system32\drivers\`)
}

// normalizeImagePath resuelve los alias que Windows permite en ImagePath: el
// prefijo de dispositivo NT (\??\) y el alias \SystemRoot\.
func normalizeImagePath(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))
	p = strings.TrimPrefix(p, `\??\`)
	if strings.HasPrefix(p, `\systemroot\`) {
		p = `c:\windows\` + p[len(`\systemroot\`):]
	}
	return p
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/services/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/services/
git commit -m "feat: parseo puro del subárbol Services y heurística de driver no estándar"
```

---

### Task 4: Parseo puro de XML de tareas (`internal/winfs/scheduler/taskxml.go`)

**Files:**
- Create: `internal/winfs/scheduler/taskxml.go`
- Test: `internal/winfs/scheduler/taskxml_test.go`

**Interfaces:**
- Consumes: `wintext.DecodeUTF16` (Task 1).
- Produces:
  - `type TaskDefinition struct { RelPath, Command, Arguments, Author string; Hidden bool }`
  - `func ParseTaskXML(raw []byte, relPath string) (TaskDefinition, error)`

Detalle importante: los XML de tarea reales de Windows declaran
`<?xml version="1.0" encoding="UTF-16"?>` en el prólogo. `encoding/xml` de Go rechaza cualquier
encoding declarado que no sea UTF-8/US-ASCII **a menos que** se le dé un `Decoder.CharsetReader`.
Como el contenido ya se decodificó a UTF-8 a mano (por el BOM), el `CharsetReader` no necesita
convertir nada — solo existe para que el decoder no aborte al leer la declaración. Esto no agrega
ninguna dependencia externa: la firma de `CharsetReader` es de la propia stdlib.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/scheduler/taskxml_test.go
package scheduler

import (
	"encoding/binary"
	"testing"
)

const sampleTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>DESKTOP-ABC\User</Author>
  </RegistrationInfo>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Temp\loader.exe</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>`

// utf16LEWithBOM codifica s como UTF-16LE con BOM inicial, igual que los XML
// de tareas que escribe el Task Scheduler real.
func utf16LEWithBOM(s string) []byte {
	buf := []byte{0xFF, 0xFE}
	for _, r := range s {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(r)) // el fixture no usa caracteres fuera del BMP
		buf = append(buf, b...)
	}
	return buf
}

func TestParseTaskXMLUTF16WithBOM(t *testing.T) {
	raw := utf16LEWithBOM(sampleTaskXML)
	got, err := ParseTaskXML(raw, `Microsoft\Windows\Foo\Bar`)
	if err != nil {
		t.Fatalf("ParseTaskXML: %v", err)
	}
	if got.Command != `C:\Temp\loader.exe` {
		t.Errorf("Command = %q", got.Command)
	}
	if got.Arguments != "-silent" {
		t.Errorf("Arguments = %q", got.Arguments)
	}
	if !got.Hidden {
		t.Error("Hidden = false, want true")
	}
	if got.Author != `DESKTOP-ABC\User` {
		t.Errorf("Author = %q", got.Author)
	}
	if got.RelPath != `Microsoft\Windows\Foo\Bar` {
		t.Errorf("RelPath = %q", got.RelPath)
	}
}

func TestParseTaskXMLPlainUTF8(t *testing.T) {
	got, err := ParseTaskXML([]byte(sampleTaskXML), `Foo\Bar`)
	if err != nil {
		t.Fatalf("ParseTaskXML: %v", err)
	}
	if got.Command != `C:\Temp\loader.exe` {
		t.Errorf("Command = %q", got.Command)
	}
}

func TestParseTaskXMLCorrupt(t *testing.T) {
	if _, err := ParseTaskXML([]byte("no es xml"), "x"); err == nil {
		t.Fatal("esperaba error con contenido corrupto")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/scheduler/`
Expected: FAIL de compilación — `undefined: ParseTaskXML`, `undefined: TaskDefinition`.

- [ ] **Step 3: Escribir `taskxml.go`**

```go
// internal/winfs/scheduler/taskxml.go
package scheduler

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// TaskDefinition es una tarea programada parseada desde su XML.
type TaskDefinition struct {
	RelPath   string // ruta relativa bajo Tasks\, ej. "Microsoft\Windows\Foo\Bar"
	Command   string // <Actions><Exec><Command>
	Arguments string // <Actions><Exec><Arguments>
	Hidden    bool   // <Settings><Hidden>
	Author    string // <RegistrationInfo><Author>
}

// taskXML mapea los campos forenses relevantes del XML de definición de
// tarea. Sin namespace explícito en los tags: encoding/xml empareja por
// nombre local e ignora el namespace por defecto, y el XML real usa un
// namespace fijo de Microsoft que no aporta nada distinguir aquí.
type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Settings struct {
		Hidden bool `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// ParseTaskXML decodifica un archivo de definición de tarea (UTF-16 con BOM,
// o UTF-8) y extrae los campos forenses relevantes.
func ParseTaskXML(raw []byte, relPath string) (TaskDefinition, error) {
	content := decodeXMLBytes(raw)
	dec := xml.NewDecoder(strings.NewReader(content))
	// El contenido ya está en UTF-8 (se decodificó arriba a mano); este
	// CharsetReader es un passthrough que solo evita que encoding/xml aborte
	// al ver la declaración <?xml encoding="UTF-16"?> que trae todo XML de
	// tarea real de Windows. No requiere ninguna dependencia externa.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var t taskXML
	if err := dec.Decode(&t); err != nil {
		return TaskDefinition{}, fmt.Errorf("parseo XML de tarea: %w", err)
	}
	return TaskDefinition{
		RelPath:   relPath,
		Command:   t.Actions.Exec.Command,
		Arguments: t.Actions.Exec.Arguments,
		Hidden:    t.Settings.Hidden,
		Author:    t.RegistrationInfo.Author,
	}, nil
}

// decodeXMLBytes detecta un BOM UTF-16LE (0xFF 0xFE) al inicio del buffer y
// lo decodifica a UTF-8; si no hay BOM, asume que ya es UTF-8/ASCII.
func decodeXMLBytes(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		return wintext.DecodeUTF16(raw[2:])
	}
	return string(raw)
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/scheduler/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/scheduler/taskxml.go internal/winfs/scheduler/taskxml_test.go
git commit -m "feat: parseo puro de XML de tareas programadas"
```

---

### Task 5: Parseo puro de `TaskCache\Tree` y cross-check de desincronización

**Files:**
- Create: `internal/winfs/scheduler/taskcache.go`
- Create: `internal/winfs/scheduler/diff.go`
- Test: `internal/winfs/scheduler/taskcache_test.go`
- Test: `internal/winfs/scheduler/diff_test.go`

**Interfaces:**
- Consumes: `reghive.Key` (Fase 1-2); `wintext.DecodeUTF16` (Task 1); `reghivetest.Builder`
  (Task 2, solo en el test); `TaskDefinition` (Task 4).
- Produces:
  - `type CachedTask struct { RelPath, ID string }`
  - `func WalkTaskCacheTree(treeKey *reghive.Key) ([]CachedTask, error)`
  - `type DesyncKind string` con constantes `HiveOnly`, `FileOnly`
  - `type Desync struct { RelPath string; Kind DesyncKind; TaskCacheID string }`
  - `func DiffTasks(onDisk []TaskDefinition, cached []CachedTask) []Desync`

- [ ] **Step 1: Escribir los tests que fallan**

```go
// internal/winfs/scheduler/taskcache_test.go
package scheduler

import (
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/reghive/reghivetest"
)

func encodeUTF16NullTerminated(s string) []byte {
	b := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func TestWalkTaskCacheTree(t *testing.T) {
	b := reghivetest.NewBuilder()

	idVal := b.AddValue("Id", encodeUTF16NullTerminated(`{11111111-1111-1111-1111-111111111111}`), 1)
	leaf := b.AddKey("Bar", nil, []uint32{idVal})
	folder := b.AddKey("Foo", []uint32{leaf}, nil) // carpeta: sin valor Id
	root := b.AddKey("Tree", []uint32{folder}, nil)

	data := b.Build(root)
	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	treeKey, err := h.OpenKey("")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}

	got, err := WalkTaskCacheTree(treeKey)
	if err != nil {
		t.Fatalf("WalkTaskCacheTree: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1: %+v", len(got), got)
	}
	if got[0].RelPath != `Foo\Bar` {
		t.Errorf(`RelPath = %q, want "Foo\Bar"`, got[0].RelPath)
	}
	if got[0].ID != `{11111111-1111-1111-1111-111111111111}` {
		t.Errorf("ID = %q", got[0].ID)
	}
}

func TestWalkTaskCacheTreeEmptyTree(t *testing.T) {
	b := reghivetest.NewBuilder()
	root := b.AddKey("Tree", nil, nil)
	data := b.Build(root)
	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	treeKey, _ := h.OpenKey("")
	got, err := WalkTaskCacheTree(treeKey)
	if err != nil {
		t.Fatalf("WalkTaskCacheTree: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got = %+v, want empty", got)
	}
}
```

```go
// internal/winfs/scheduler/diff_test.go
package scheduler

import "testing"

func TestDiffTasksNoDesync(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `Foo\Bar`}}
	cached := []CachedTask{{RelPath: `Foo\Bar`, ID: "{GUID}"}}
	got := DiffTasks(onDisk, cached)
	if len(got) != 0 {
		t.Fatalf("DiffTasks = %+v, want empty", got)
	}
}

func TestDiffTasksHiveOnly(t *testing.T) {
	cached := []CachedTask{{RelPath: `Foo\Ghost`, ID: "{GUID-1}"}}
	got := DiffTasks(nil, cached)
	if len(got) != 1 || got[0].Kind != HiveOnly || got[0].TaskCacheID != "{GUID-1}" || got[0].RelPath != `Foo\Ghost` {
		t.Fatalf("DiffTasks = %+v", got)
	}
}

func TestDiffTasksFileOnly(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `Foo\Orphan`}}
	got := DiffTasks(onDisk, nil)
	if len(got) != 1 || got[0].Kind != FileOnly || got[0].RelPath != `Foo\Orphan` {
		t.Fatalf("DiffTasks = %+v", got)
	}
}

func TestDiffTasksMixed(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `A`}, {RelPath: `B`}}
	cached := []CachedTask{{RelPath: `A`, ID: "{A}"}, {RelPath: `C`, ID: "{C}"}}
	got := DiffTasks(onDisk, cached)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2: %+v", len(got), got)
	}
}
```

- [ ] **Step 2: Correr los tests para verificar que fallan**

Run: `go test ./internal/winfs/scheduler/`
Expected: FAIL de compilación — `undefined: WalkTaskCacheTree`, `undefined: CachedTask`,
`undefined: DiffTasks`, `undefined: HiveOnly`, `undefined: FileOnly`, `undefined: Desync`.

- [ ] **Step 3: Escribir `taskcache.go`**

```go
// internal/winfs/scheduler/taskcache.go
package scheduler

import (
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// CachedTask es una entrada hoja del árbol TaskCache\Tree con su Id (GUID).
type CachedTask struct {
	RelPath string // misma convención de ruta relativa que TaskDefinition
	ID      string // valor "Id" (GUID) de la subclave hoja
}

// WalkTaskCacheTree recorre recursivamente la clave Tree y devuelve toda
// hoja que tenga un valor "Id" (las claves intermedias sin ese valor son
// carpetas, no tareas).
func WalkTaskCacheTree(treeKey *reghive.Key) ([]CachedTask, error) {
	return walkTree(treeKey, ""), nil
}

func walkTree(key *reghive.Key, prefix string) []CachedTask {
	var out []CachedTask
	if raw, _, err := key.Value("Id"); err == nil {
		out = append(out, CachedTask{RelPath: prefix, ID: wintext.DecodeUTF16(raw)})
	}
	subs, err := key.Subkeys()
	if err != nil {
		return out // celda malformada: se corta ahí, no aborta el resto del árbol
	}
	for _, s := range subs {
		childPath := s.Name()
		if prefix != "" {
			childPath = prefix + `\` + s.Name()
		}
		out = append(out, walkTree(s, childPath)...)
	}
	return out
}
```

- [ ] **Step 4: Escribir `diff.go`**

```go
// internal/winfs/scheduler/diff.go
package scheduler

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
// recibir el listado completo: una tarea borrada del disco por definición no
// puede pasar un filtro de "sospechoso" (ya no existe para evaluarla), así
// que filtrar antes de diffear perdería justamente la detección hive_only.
func DiffTasks(onDisk []TaskDefinition, cached []CachedTask) []Desync {
	diskSet := make(map[string]bool, len(onDisk))
	for _, t := range onDisk {
		diskSet[t.RelPath] = true
	}
	cacheSet := make(map[string]bool, len(cached))
	for _, c := range cached {
		cacheSet[c.RelPath] = true
	}

	var out []Desync
	for _, c := range cached {
		if !diskSet[c.RelPath] {
			out = append(out, Desync{RelPath: c.RelPath, Kind: HiveOnly, TaskCacheID: c.ID})
		}
	}
	for _, t := range onDisk {
		if !cacheSet[t.RelPath] {
			out = append(out, Desync{RelPath: t.RelPath, Kind: FileOnly})
		}
	}
	return out
}
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/scheduler/`
Expected: PASS (los 4 archivos del paquete `scheduler` compilan y testean juntos).

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/scheduler/taskcache.go internal/winfs/scheduler/diff.go internal/winfs/scheduler/taskcache_test.go internal/winfs/scheduler/diff_test.go
git commit -m "feat: parseo de TaskCache\\Tree y cross-check de desincronización XML-registro"
```

---

### Task 6: Colector de Servicios (`internal/collector/services`)

**Files:**
- Create: `internal/collector/services/services.go`
- Test: `internal/collector/services/services_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact`, `collector.PriorityRegistry` (Fase 1);
  `reghive.Open`, `reghive.Key.OpenKey` (Fase 1-2); `services.ParseServices`,
  `services.IsNonMicrosoftDriver`, `services.DriverService` (Task 3).
- Produces:
  - `type Collector struct { HivePath string }`
  - `func New(systemHivePath string) *Collector`
  - `Name() string` = `"services"`, `Priority() int` = `collector.PriorityRegistry`,
    `Collect(ctx) ([]collector.Artifact, error)`.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/services/services_test.go
package services

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New(`C:\Windows\System32\config\SYSTEM`)
	if c.Name() != "services" {
		t.Fatalf("Name = %q, want services", c.Name())
	}
	if c.Priority() != collector.PriorityRegistry {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityRegistry)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New(`C:\Windows\System32\config\SYSTEM`)
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea contra el
// hive real; hace skip si no hay acceso (hive bloqueado sin VSS, o no-Windows).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New(`C:\Windows\System32\config\SYSTEM`).Collect(context.Background())
	if err != nil {
		t.Skipf("hive SYSTEM no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "service_driver" {
			t.Fatalf("Type = %q, want service_driver", a.Type)
		}
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/services/`
Expected: FAIL de compilación — `undefined: New` (paquete `internal/collector/services` no
existe todavía; nota: hay OTRO paquete `services` en `internal/winfs/services` de la Tarea 3 — no
hay conflicto porque son paquetes distintos en directorios distintos, pero el Step 3 usa un alias
de import para evitar la colisión de nombres dentro del mismo archivo).

- [ ] **Step 3: Escribir `services.go`**

```go
// internal/collector/services/services.go
package services

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// Collector recolecta drivers no estándar del subárbol Services del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "services" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		root, err = h.OpenKey(`ControlSet002\Services`)
		if err != nil {
			return nil, err
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0)
	for _, s := range all {
		select {
		case <-ctx.Done():
			return artifacts, ctx.Err()
		default:
		}
		if !winservices.IsNonMicrosoftDriver(s) {
			continue
		}
		b, _ := json.Marshal(s)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "service_driver",
			Source:    s.ImagePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/services/`
Expected: PASS (`TestCollectReturnsArtifactsOrError` hace `t.Skip` en un host sin ese hive exacto
— cualquier host que no sea Windows con esa ruta literal).

- [ ] **Step 5: Commit**

```bash
git add internal/collector/services/
git commit -m "feat: colector de servicios no estándar"
```

---

### Task 7: Colector de Tareas Programadas (`internal/collector/scheduler`)

**Files:**
- Create: `internal/collector/scheduler/scheduler.go`
- Test: `internal/collector/scheduler/scheduler_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact`, `collector.PriorityDisk` (Fase 1);
  `reghive.Open`, `reghive.Key.OpenKey` (Fase 1-2); `fsforensic.HasForensicExtension`,
  `fsforensic.IsSuspiciousName` (Fase 3A); `scheduler.ParseTaskXML`, `scheduler.TaskDefinition`
  (Task 4); `scheduler.WalkTaskCacheTree`, `scheduler.CachedTask`, `scheduler.DiffTasks` (Task 5).
- Produces:
  - `type Collector struct { TasksDir, SoftwareHivePath string }`
  - `func New(tasksDir, softwareHivePath string) *Collector`
  - `Name() string` = `"scheduled_tasks"`, `Priority() int` = `collector.PriorityDisk`,
    `Collect(ctx) ([]collector.Artifact, error)`.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/scheduler/scheduler_test.go
package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New(`C:\Windows\System32\Tasks`, `C:\Windows\System32\config\SOFTWARE`)
	if c.Name() != "scheduled_tasks" {
		t.Fatalf("Name = %q, want scheduled_tasks", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New(`C:\Windows\System32\Tasks`, `C:\Windows\System32\config\SOFTWARE`)
}

// TestCollectWithSyntheticTasksDir valida el flujo completo sobre un
// directorio temporal con dos tareas: una oculta (debe reportarse) y una
// normal sin nada sospechoso (no debe reportarse). El hive SOFTWARE no
// existe en este test -> el cross-check se omite sin abortar el colector.
func TestCollectWithSyntheticTasksDir(t *testing.T) {
	dir := t.TempDir()
	hiddenXML := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>true</Hidden></Settings>
  <Actions><Exec><Command>C:\Temp\hidden.exe</Command></Exec></Actions>
</Task>`
	normalXML := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>false</Hidden></Settings>
  <Actions><Exec><Command>C:\Program Files\App\updater.exe</Command></Exec></Actions>
</Task>`
	if err := os.WriteFile(filepath.Join(dir, "HiddenTask"), []byte(hiddenXML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "NormalTask"), []byte(normalXML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := New(dir, filepath.Join(dir, "no-existe.hve"))
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var sawHidden bool
	for _, a := range arts {
		if a.Type == "scheduled_task" {
			sawHidden = true
			if a.Source != "HiddenTask" {
				t.Errorf("Source = %q, want HiddenTask (la tarea normal no debería reportarse)", a.Source)
			}
		}
		if a.Type == "scheduled_task_desync" {
			t.Errorf("no se esperaba desync sin hive SOFTWARE: %+v", a)
		}
	}
	if !sawHidden {
		t.Fatal("esperaba un artifact scheduled_task para la tarea oculta")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/scheduler/`
Expected: FAIL de compilación — `undefined: New`.

- [ ] **Step 3: Escribir `scheduler.go`**

```go
// internal/collector/scheduler/scheduler.go
package scheduler

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
)

// Collector recolecta tareas programadas sospechosas/ocultas y su cross-check
// contra TaskCache.
type Collector struct {
	TasksDir         string
	SoftwareHivePath string
}

// New crea el colector con la carpeta Tasks y el hive SOFTWARE dados.
func New(tasksDir, softwareHivePath string) *Collector {
	return &Collector{TasksDir: tasksDir, SoftwareHivePath: softwareHivePath}
}

func (c *Collector) Name() string  { return "scheduled_tasks" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	onDisk, walkErr := c.readTasksDir(ctx)
	if walkErr != nil && len(onDisk) == 0 {
		return nil, walkErr // no se pudo enumerar nada: falla dura
	}

	artifacts := make([]collector.Artifact, 0)

	// Si el hive SOFTWARE no está disponible, se omite el cross-check pero se
	// sigue con las tareas en disco: perder toda la señal de tareas por un
	// fallo transitorio de VSS en una sola de las dos fuentes es peor que
	// degradar con gracia.
	if cached, err := c.readTaskCache(); err == nil {
		for _, d := range winscheduler.DiffTasks(onDisk, cached) {
			b, _ := json.Marshal(d)
			artifacts = append(artifacts, collector.Artifact{
				Type:      "scheduled_task_desync",
				Source:    d.RelPath,
				Data:      b,
				Collected: time.Now(),
			})
		}
	}

	for _, t := range onDisk {
		if !isReportable(t) {
			continue
		}
		b, _ := json.Marshal(t)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "scheduled_task",
			Source:    t.RelPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, walkErr
}

// isReportable filtra a tareas ocultas o con comando/argumentos forenses o sospechosos.
func isReportable(t winscheduler.TaskDefinition) bool {
	if t.Hidden {
		return true
	}
	return fsforensic.HasForensicExtension(t.Command) ||
		fsforensic.IsSuspiciousName(t.Command) ||
		fsforensic.IsSuspiciousName(t.Arguments)
}

// readTasksDir enumera recursivamente TasksDir y parsea cada archivo como
// definición de tarea. Un archivo individual corrupto o inaccesible se
// omite; solo un fallo en la raíz misma es un error real.
func (c *Collector) readTasksDir(ctx context.Context) ([]winscheduler.TaskDefinition, error) {
	var out []winscheduler.TaskDefinition
	err := filepath.WalkDir(c.TasksDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == c.TasksDir {
				return err
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(c.TasksDir, path)
		if err != nil {
			return nil
		}
		t, err := winscheduler.ParseTaskXML(raw, rel)
		if err != nil {
			return nil // XML corrupto o no-XML: se omite
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

// readTaskCache abre el hive SOFTWARE y camina TaskCache\Tree.
func (c *Collector) readTaskCache() ([]winscheduler.CachedTask, error) {
	data, err := os.ReadFile(c.SoftwareHivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	treeKey, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`)
	if err != nil {
		return nil, err
	}
	return winscheduler.WalkTaskCacheTree(treeKey)
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/scheduler/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/scheduler/
git commit -m "feat: colector de tareas programadas con cross-check XML-TaskCache"
```

---

### Task 8: Registrar ambos colectores en el entrypoint live

**Files:**
- Modify: `internal/agent/live_windows.go`

**Interfaces:**
- Consumes: `services.New` (Task 6), `scheduler.New` (Task 7), `vss.PathIn` (ya existente).
- Produces: nada nuevo — solo wiring.

- [ ] **Step 1: Agregar los imports**

En `internal/agent/live_windows.go`, agregar al bloque de imports (junto a los otros
colectores), con alias para no chocar con los paquetes homónimos de `winfs`:

```go
	schedulercol "github.com/telagem/agent-windows/internal/collector/scheduler"
	servicescol "github.com/telagem/agent-windows/internal/collector/services"
```

- [ ] **Step 2: Agregar la resolución del hive SOFTWARE**

Reemplazar:
```go
	systemHive := `C:\Windows\System32\config\SYSTEM`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
	}
```
por:
```go
	systemHive := `C:\Windows\System32\config\SYSTEM`
	softwareHive := `C:\Windows\System32\config\SOFTWARE`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		softwareHive = vss.PathIn(snap, `Windows\System32\config\SOFTWARE`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
	}
```

- [ ] **Step 3: Registrar ambos colectores en el slice**

Reemplazar:
```go
	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		deletedcol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
	}
```
por:
```go
	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		deletedcol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
		servicescol.New(systemHive),
		schedulercol.New(`C:\Windows\System32\Tasks`, softwareHive),
	}
```

- [ ] **Step 4: Verificar build completo y toda la suite**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `go test ./...`
Expected: PASS en todos los paquetes.
Run: `GOOS=windows GOARCH=amd64 go vet ./...`
Expected: sin advertencias.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/live_windows.go
git commit -m "feat: registrar colectores de servicios y tareas programadas en el entrypoint live"
```

---

## Self-review del plan

**Cobertura del spec:** cada sección de `2026-07-29-agente-forense-windows-fase-3c-persistencia-design.md`
tiene tarea: helper `wintext` → Task 1; `services` puro + heurística → Task 3; `scheduler` puro
(XML, TaskCache, diff) → Tasks 4-5; colectores → Tasks 6-7; wiring → Task 8. El punto "ningún
paquete nuevo lleva build tag windows" se cumple en todos los archivos creados (ninguno tiene
`//go:build`). El punto "DiffTasks recibe el listado completo, no filtrado" está reflejado
literalmente en el colector (Task 7: `DiffTasks(onDisk, cached)` usa el `onDisk` sin filtrar,
el filtro `isReportable` se aplica después, en un bucle separado).

**Placeholders:** ninguno — cada step tiene código completo y ejecutable, sin "TODO" ni
"similar a la tarea anterior".

**Consistencia de tipos:** `TaskDefinition` (Task 4) se consume tal cual en `diff.go` (Task 5) y
en `scheduler.go` del colector (Task 7) sin cambios de forma. `DriverService` (Task 3) se
consume tal cual en `services.go` del colector (Task 6). `CachedTask`/`Desync`/`DesyncKind`
(Task 5) se consumen tal cual en el colector (Task 7). Los nombres de import alias
(`winservices`, `winscheduler`, `servicescol`, `schedulercol`) son consistentes entre la
declaración en Task 6/7/8 y su uso.

## Notas de cierre

- Con esta fase, `agent-windows` cubre las tres superficies de persistencia identificadas en la
  comparación con KellerSS-PC: servicios/drivers, tareas programadas, y manipulación activa de
  rastros de tareas (cross-check).
- **Fuera de alcance** (ver spec): validación de firma Authenticode; AuthModule, sustitución de
  disco, crash/WER, Temp, PCA, Event Log, hosts file, firmas de cheats conocidos — cada uno
  necesita su propio brainstorming; motor de correlación/severidad (Fase 4/5).
