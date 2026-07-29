# Agente Forense Windows — Fase 3B-2 (Acceso Raw + Recuperación de Entradas Borradas) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recuperar metadatos forenses de archivos **eliminados** del volumen `C:` (ejecutables/scripts/nombres sospechosos) leyendo el `$MFT` a nivel de disco crudo, enumerando los registros con `InUse = 0` que la API del filesystem ya no expone, y reportando cada uno como artefacto con ruta reconstruida y veredicto de timestomping.

**Architecture:** Se lee el sector 0 (`$Boot`) para ubicar el `$MFT`, se decodifican los *data runs* del `$DATA` del registro 0 para conocer sus *extents* en disco, y se barren en *streaming* todos los registros del MFT (incluidos los borrados). El parseo de registro FILE y la detección de timestomping se reutilizan de la Fase 3B-1 (funciones puras, ahora exportadas). Todo el I/O crudo se aísla en el nuevo paquete `internal/winfs/ntfs`; el parseo del boot sector y de data runs es puro (testeable en cualquier host) y solo `ntfs_windows.go` toca syscalls.

**Tech Stack:** Go 1.25+, `golang.org/x/sys/windows` (CreateFile, ReadFile con OVERLAPPED para lectura por offset), stdlib (`encoding/binary`, `errors`, `fmt`). Sin CGO, sin dependencias externas en runtime.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Go 1.25+ como mínimo (go.mod declara `go 1.25.0`). Module path: `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; sin dependencias externas en runtime (stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` INFO (el `runner` recupera panics y propaga errores).
- Nunca recolectar contenido ni nombres de archivos personales: solo metadatos forenses. Se decodifican **únicamente** los data runs del propio `$MFT` (registro 0); jamás data runs de `$DATA` de archivos arbitrarios. El filtro `fsforensic` garantiza que no se reporten nombres personales.
- Código en inglés (identificadores); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Estructura de archivos

- `internal/winfs/mft/record.go` — (modificar) exportar `ParseRecord`/`ApplyFixup`, exponer `Record.ParentRef`.
- `internal/winfs/mft/timestomp.go` — (modificar) exportar `DetectTimestomp`.
- `internal/winfs/ntfs/bootsector.go` — parseo puro del boot sector `$Boot`.
- `internal/winfs/ntfs/dataruns.go` — decodificación pura de data runs + localización del `$DATA` no-residente.
- `internal/winfs/ntfs/ntfs_windows.go` — acceso raw a `\\.\C:`, barrido del MFT, recuperación de borrados.
- `internal/winfs/ntfs/ntfs_other.go` — stub no-Windows.
- `internal/collector/deleted/deleted.go` — adaptador al contrato `collector.Collector`.
- `internal/agent/live_windows.go` — (modificar) registrar el colector.

---

### Task 1: Preparar `mft` para reutilización (exportar API + exponer `ParentRef`)

Refactor sobre el paquete `mft` de 3B-1: se exportan las tres funciones que `ntfs` reutilizará y se expone el `ParentRef` del `$FILE_NAME` (necesario para resolver rutas desde el barrido raw). Los tipos `Record`, `Timestamps`, `Verdict` y `ErrBadSignature` ya son públicos. Es refactor sobre código que se está tocando; los tests existentes deben quedar en verde.

**Files:**
- Modify: `internal/winfs/mft/record.go` (renombrar `parseRecord`→`ParseRecord`, `applyFixup`→`ApplyFixup`; agregar campo `ParentRef` y poblarlo)
- Modify: `internal/winfs/mft/timestomp.go` (renombrar `detectTimestomp`→`DetectTimestomp`)
- Modify: `internal/winfs/mft/mft_windows.go` (adaptar llamadas internas)
- Modify: `internal/winfs/mft/record_test.go` (adaptar llamadas)
- Modify: `internal/winfs/mft/timestomp_test.go` (adaptar llamadas)

**Interfaces:**
- Consumes: nada nuevo.
- Produces:
  - `func ParseRecord(buf []byte) (Record, error)`
  - `func ApplyFixup(buf []byte) ([]byte, error)`
  - `func DetectTimestomp(si, fn Timestamps) Verdict`
  - `Record` gana el campo `ParentRef uint64` (referencia MFT del directorio padre, de los primeros 8 bytes del `$FN`).

- [ ] **Step 1: Renombrar en `record.go` y agregar `ParentRef`**

En `internal/winfs/mft/record.go`, agregar el campo al struct `Record` (después de `FileName`):
```go
	FileName  string
	ParentRef uint64 // referencia MFT del directorio padre (de los 8 primeros bytes del $FN)
```
Renombrar la definición y su comentario:
```go
// ParseRecord parsea un registro FILE del MFT: valida firma, aplica el update
// sequence array fixup y extrae SI (0x10) y FN (0x30) de los atributos residentes.
func ParseRecord(buf []byte) (Record, error) {
```
Dentro de `ParseRecord`, actualizar la llamada interna:
```go
	fixed, err := ApplyFixup(buf)
```
Renombrar la definición del fixup y su comentario:
```go
// ApplyFixup restaura los últimos 2 bytes de cada sector, que NTFS reemplaza por
// el update sequence number al escribir. Devuelve una copia corregida del buffer.
func ApplyFixup(buf []byte) ([]byte, error) {
```
En `applyFileName`, poblar `ParentRef` junto a los demás campos (después del guard de namespace):
```go
	r.FN = parseTimestamps(c, 0x08)
	r.FileName = decodeUTF16(c[0x42:nameEnd])
	r.ParentRef = binary.LittleEndian.Uint64(c[0x00:0x08])
	r.HasFN = true
	r.fnNamespace = namespace
```

- [ ] **Step 2: Renombrar en `timestomp.go`**

En `internal/winfs/mft/timestomp.go`, renombrar la definición y su comentario:
```go
// DetectTimestomp compara SI vs FN. Marca backdating imposible naturalmente:
// SI.Created (o SI.Modified) anterior a FN.Created, que es cuando se creó la
// entrada de nombre. Los ceros (timestamps ausentes) no gatillan.
func DetectTimestomp(si, fn Timestamps) Verdict {
```

- [ ] **Step 3: Adaptar llamadas internas en `mft_windows.go`**

En `internal/winfs/mft/mft_windows.go`, reemplazar la línea 74:
```go
		v := detectTimestomp(rec.SI, rec.FN)
```
por:
```go
		v := DetectTimestomp(rec.SI, rec.FN)
```
Y la línea final de `getFileRecord`:
```go
	return parseRecord(out[12 : 12+recLen])
```
por:
```go
	return ParseRecord(out[12 : 12+recLen])
```

- [ ] **Step 4: Adaptar los tests del paquete**

En `internal/winfs/mft/record_test.go`, reemplazar **todas** las apariciones de `parseRecord(` por `ParseRecord(` (llamadas en las líneas de `rec, err := parseRecord(buf)` y `if _, err := parseRecord(buf)`). Los mensajes de `t.Fatalf("parseRecord: %v", err)` pueden quedar igual (son texto libre) o actualizarse a `ParseRecord`.

En `internal/winfs/mft/timestomp_test.go`, reemplazar **todas** las apariciones de `detectTimestomp(` por `DetectTimestomp(`.

- [ ] **Step 5: Correr los tests y el build de Windows**

Run: `go test ./internal/winfs/mft/`
Expected: PASS (los tests puros siguen verdes con los nuevos nombres).
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./internal/winfs/mft/`
Expected: sin advertencias.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/mft/record.go internal/winfs/mft/timestomp.go internal/winfs/mft/mft_windows.go internal/winfs/mft/record_test.go internal/winfs/mft/timestomp_test.go
git commit -m "refactor: exportar ParseRecord/DetectTimestomp/ApplyFixup y exponer ParentRef"
```

---

### Task 2: Parseo puro del boot sector (`bootsector.go`)

**Files:**
- Create: `internal/winfs/ntfs/bootsector.go`
- Test: `internal/winfs/ntfs/bootsector_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type BootSector struct { BytesPerSector uint16; SectorsPerCluster uint8; MFTCluster uint64; BytesPerRecord int; ClusterSize int }`
  - `var ErrNotNTFS = errors.New(...)`
  - `func ParseBootSector(sector []byte) (BootSector, error)` — valida la firma OEM `"NTFS    "` y extrae la geometría desde los primeros bytes del sector 0.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/ntfs/bootsector_test.go
package ntfs

import (
	"encoding/binary"
	"errors"
	"testing"
)

// buildBootSector arma un boot sector NTFS sintético de 512 bytes.
// clustersPerRec sigue la convención NTFS: negativo → 2^(-valor) bytes por registro.
func buildBootSector(bps uint16, spc uint8, mftLCN uint64, clustersPerRec int8) []byte {
	b := make([]byte, 512)
	copy(b[0x03:0x0B], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(b[0x0B:0x0D], bps)
	b[0x0D] = spc
	binary.LittleEndian.PutUint64(b[0x30:0x38], mftLCN)
	b[0x40] = byte(clustersPerRec)
	return b
}

func TestParseBootSectorValid(t *testing.T) {
	b := buildBootSector(512, 8, 786432, -10) // registro = 2^10 = 1024 bytes
	bs, err := ParseBootSector(b)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.BytesPerSector != 512 || bs.SectorsPerCluster != 8 {
		t.Errorf("geometría = %d/%d, want 512/8", bs.BytesPerSector, bs.SectorsPerCluster)
	}
	if bs.ClusterSize != 4096 {
		t.Errorf("ClusterSize = %d, want 4096", bs.ClusterSize)
	}
	if bs.MFTCluster != 786432 {
		t.Errorf("MFTCluster = %d, want 786432", bs.MFTCluster)
	}
	if bs.BytesPerRecord != 1024 {
		t.Errorf("BytesPerRecord = %d, want 1024", bs.BytesPerRecord)
	}
}

func TestParseBootSectorNotNTFS(t *testing.T) {
	b := buildBootSector(512, 8, 100, -10)
	copy(b[0x03:0x0B], []byte("XXXXXXXX"))
	if _, err := ParseBootSector(b); !errors.Is(err, ErrNotNTFS) {
		t.Fatalf("esperaba ErrNotNTFS, obtuve %v", err)
	}
}

func TestParseBootSectorPositiveClustersPerRecord(t *testing.T) {
	// clustersPerRec = 1 → registro = 1 clúster = 512*2 = 1024 bytes.
	b := buildBootSector(512, 2, 100, 1)
	bs, err := ParseBootSector(b)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.BytesPerRecord != 1024 {
		t.Errorf("BytesPerRecord = %d, want 1024", bs.BytesPerRecord)
	}
}

func TestParseBootSectorBadGeometry(t *testing.T) {
	b := buildBootSector(999, 8, 100, -10) // bytes por sector inválido
	if _, err := ParseBootSector(b); err == nil {
		t.Fatal("esperaba error por geometría inválida")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/ntfs/`
Expected: FAIL de compilación — `undefined: ParseBootSector`, `undefined: ErrNotNTFS`.

- [ ] **Step 3: Escribir `bootsector.go`**

```go
// internal/winfs/ntfs/bootsector.go
package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotNTFS indica que el sector 0 no tiene la firma OEM "NTFS".
var ErrNotNTFS = errors.New("volumen no es NTFS (falta firma OEM)")

// BootSector describe la geometría NTFS necesaria para ubicar y leer el $MFT.
type BootSector struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	MFTCluster        uint64 // LCN del primer clúster del $MFT
	BytesPerRecord    int    // tamaño de un registro FILE (típico 1024)
	ClusterSize       int    // BytesPerSector * SectorsPerCluster
}

// ParseBootSector valida la firma NTFS y extrae la geometría del sector 0 (>=512 bytes).
func ParseBootSector(sector []byte) (BootSector, error) {
	if len(sector) < 0x50 {
		return BootSector{}, errors.New("boot sector truncado")
	}
	if string(sector[0x03:0x0B]) != "NTFS    " {
		return BootSector{}, ErrNotNTFS
	}
	bps := binary.LittleEndian.Uint16(sector[0x0B:0x0D])
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return BootSector{}, fmt.Errorf("bytes por sector inválido: %d", bps)
	}
	spc := sector[0x0D]
	if spc == 0 {
		return BootSector{}, errors.New("sectores por clúster es cero")
	}
	clusterSize := int(bps) * int(spc)

	mftCluster := binary.LittleEndian.Uint64(sector[0x30:0x38])

	// ClustersPerFileRecordSegment: si es positivo, nº de clústers por registro;
	// si es negativo, el tamaño del registro es 2^(-valor) bytes.
	raw := int8(sector[0x40])
	var bytesPerRecord int
	if raw >= 0 {
		bytesPerRecord = int(raw) * clusterSize
	} else {
		bytesPerRecord = 1 << uint(-raw)
	}
	if bytesPerRecord < 512 {
		return BootSector{}, fmt.Errorf("tamaño de registro inválido: %d", bytesPerRecord)
	}

	return BootSector{
		BytesPerSector:    bps,
		SectorsPerCluster: spc,
		MFTCluster:        mftCluster,
		BytesPerRecord:    bytesPerRecord,
		ClusterSize:       clusterSize,
	}, nil
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/ntfs/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/ntfs/bootsector.go internal/winfs/ntfs/bootsector_test.go
git commit -m "feat: parseo puro del boot sector NTFS ($Boot)"
```

---

### Task 3: Decodificación de data runs y localización del `$DATA` (`dataruns.go`)

**Files:**
- Create: `internal/winfs/ntfs/dataruns.go`
- Test: `internal/winfs/ntfs/dataruns_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type Extent struct { StartLCN uint64; Length uint64 }`
  - `func DecodeDataRuns(runs []byte) ([]Extent, error)` — decodifica los mapping pairs (offset con signo relativo al run previo) en una lista de extents absolutos.
  - `func nonResidentDataRuns(recordBuf []byte) ([]byte, error)` — (no exportada) localiza el atributo `$DATA` (0x80) no-residente en un registro FILE con fixup aplicado y devuelve los bytes de sus mapping pairs.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/ntfs/dataruns_test.go
package ntfs

import (
	"encoding/binary"
	"testing"
)

func TestDecodeDataRunsSingle(t *testing.T) {
	// header 0x21 → lenSize=1, offSize=2; length=0x08; offset=0x0140 (320).
	runs := []byte{0x21, 0x08, 0x40, 0x01, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 1 {
		t.Fatalf("len(ex) = %d, want 1", len(ex))
	}
	if ex[0].StartLCN != 320 || ex[0].Length != 8 {
		t.Errorf("extent = %+v, want {320, 8}", ex[0])
	}
}

func TestDecodeDataRunsMultipleContiguous(t *testing.T) {
	// run1: 0x11 len=0x30 off=0x60 → lcn=0x60. run2: 0x11 len=0x10 off=0x05 → lcn=0x65.
	runs := []byte{0x11, 0x30, 0x60, 0x11, 0x10, 0x05, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 2 || ex[0].StartLCN != 0x60 || ex[1].StartLCN != 0x65 {
		t.Fatalf("extents = %+v", ex)
	}
}

func TestDecodeDataRunsNegativeOffset(t *testing.T) {
	// run1: lcn=64. run2: off=0xFF (−1) → lcn=63.
	runs := []byte{0x11, 0x10, 0x40, 0x11, 0x10, 0xFF, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if ex[1].StartLCN != 63 {
		t.Errorf("segundo LCN = %d, want 63 (delta negativo)", ex[1].StartLCN)
	}
}

func TestDecodeDataRunsTruncated(t *testing.T) {
	runs := []byte{0x21, 0x08, 0x40} // falta un byte del offset
	if _, err := DecodeDataRuns(runs); err == nil {
		t.Fatal("esperaba error por data run truncado")
	}
}

// buildNonResidentData arma un atributo $DATA no-residente con los mapping pairs dados.
func buildNonResidentData(runs []byte) []byte {
	const hdr = 0x40 // header no-residente sin nombre; mapping pairs a 0x40
	total := hdr + len(runs)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], 0x80) // tipo $DATA
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 1 // flag no-residente
	binary.LittleEndian.PutUint16(a[0x20:0x22], hdr) // mapping pairs offset
	copy(a[hdr:], runs)
	return a
}

// buildFileRecord arma un registro FILE mínimo (sin scramble de fixup) con los atributos dados.
func buildFileRecord(attrs ...[]byte) []byte {
	buf := make([]byte, 1024)
	copy(buf[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(buf[0x04:0x06], 0x30) // USA offset
	binary.LittleEndian.PutUint16(buf[0x06:0x08], 3)    // USA count
	binary.LittleEndian.PutUint16(buf[0x14:0x16], 0x38) // primer atributo
	off := 0x38
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}
	binary.LittleEndian.PutUint32(buf[off:off+4], 0xFFFFFFFF) // terminador
	return buf
}

func TestNonResidentDataRunsLocatesData(t *testing.T) {
	runs := []byte{0x11, 0x08, 0x40, 0x00} // 1 run: lcn=0x40, len=0x08
	rec := buildFileRecord(buildNonResidentData(runs))
	got, err := nonResidentDataRuns(rec)
	if err != nil {
		t.Fatalf("nonResidentDataRuns: %v", err)
	}
	ex, err := DecodeDataRuns(got)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 1 || ex[0].StartLCN != 0x40 || ex[0].Length != 8 {
		t.Fatalf("extents = %+v", ex)
	}
}

func TestNonResidentDataRunsMissing(t *testing.T) {
	rec := buildFileRecord() // sin atributos
	if _, err := nonResidentDataRuns(rec); err == nil {
		t.Fatal("esperaba error si no hay $DATA no-residente")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/ntfs/`
Expected: FAIL de compilación — `undefined: DecodeDataRuns`, `undefined: nonResidentDataRuns`, `undefined: Extent`.

- [ ] **Step 3: Escribir `dataruns.go`**

```go
// internal/winfs/ntfs/dataruns.go
package ntfs

import (
	"encoding/binary"
	"errors"
)

// Extent es una corrida contigua de clústers del $MFT en disco.
type Extent struct {
	StartLCN uint64 // clúster lógico inicial (absoluto)
	Length   uint64 // número de clústers
}

// DecodeDataRuns decodifica los mapping pairs de un atributo $DATA no-residente:
// cada run es un byte de cabecera (nibble bajo = tamaño de la longitud, nibble
// alto = tamaño del offset) seguido de la longitud y un offset con signo relativo
// al run anterior. Cabecera 0x00 termina la lista.
func DecodeDataRuns(runs []byte) ([]Extent, error) {
	var extents []Extent
	var lcn int64 // LCN acumulado (los deltas pueden ser negativos)
	pos := 0
	for pos < len(runs) {
		header := runs[pos]
		if header == 0x00 {
			break // terminador
		}
		pos++
		lenSize := int(header & 0x0F)
		offSize := int(header >> 4)
		if lenSize == 0 || lenSize > 8 || offSize > 8 {
			return nil, errors.New("data run con tamaños de campo inválidos")
		}
		if pos+lenSize+offSize > len(runs) {
			return nil, errors.New("data run excede el buffer")
		}
		length := readLE(runs[pos : pos+lenSize])
		pos += lenSize
		if offSize == 0 {
			// Run sparse (hueco): el $MFT no debería tenerlos; se salta sin emitir.
			continue
		}
		lcn += readSignedLE(runs[pos : pos+offSize])
		pos += offSize
		if lcn < 0 || length == 0 {
			return nil, errors.New("data run con LCN o longitud inválidos")
		}
		extents = append(extents, Extent{StartLCN: uint64(lcn), Length: length})
	}
	return extents, nil
}

// readLE lee hasta 8 bytes little-endian sin signo.
func readLE(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// readSignedLE lee hasta 8 bytes little-endian con signo (complemento a dos).
func readSignedLE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var u uint64
	for i := len(b) - 1; i >= 0; i-- {
		u = u<<8 | uint64(b[i])
	}
	shift := uint(64 - 8*len(b))
	return int64(u<<shift) >> shift // extensión de signo aritmética
}

// nonResidentDataRuns localiza el atributo $DATA (0x80) no-residente dentro de un
// registro FILE con fixup ya aplicado y devuelve los bytes de sus mapping pairs.
// Necesario porque mft.ParseRecord solo extrae SI/FN residentes; el $DATA del $MFT
// lo resuelve ntfs por su cuenta.
func nonResidentDataRuns(recordBuf []byte) ([]byte, error) {
	if len(recordBuf) < 0x18 || string(recordBuf[0:4]) != "FILE" {
		return nil, errors.New("registro sin firma FILE")
	}
	off := int(binary.LittleEndian.Uint16(recordBuf[0x14:0x16]))
	for off+8 <= len(recordBuf) {
		attrType := binary.LittleEndian.Uint32(recordBuf[off : off+4])
		if attrType == 0xFFFFFFFF {
			break // terminador
		}
		attrLen := int(binary.LittleEndian.Uint32(recordBuf[off+4 : off+8]))
		if attrLen < 0x18 || off+attrLen > len(recordBuf) {
			return nil, errors.New("longitud de atributo inválida")
		}
		if attrType == 0x80 && recordBuf[off+8] == 1 { // $DATA no-residente
			mpOff := int(binary.LittleEndian.Uint16(recordBuf[off+0x20 : off+0x22]))
			start := off + mpOff
			end := off + attrLen
			if mpOff < 0x40 || start > end || end > len(recordBuf) {
				return nil, errors.New("mapping pairs offset fuera de rango")
			}
			return recordBuf[start:end], nil
		}
		off += attrLen
	}
	return nil, errors.New("$DATA no-residente no encontrado en el $MFT")
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/ntfs/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/winfs/ntfs/dataruns.go internal/winfs/ntfs/dataruns_test.go
git commit -m "feat: decodificación de data runs y localización del \$DATA no-residente"
```

---

### Task 4: Barrido raw del MFT y recuperación de borrados (`ntfs_windows.go` / `ntfs_other.go`)

**Files:**
- Create: `internal/winfs/ntfs/ntfs_windows.go`
- Create: `internal/winfs/ntfs/ntfs_other.go`
- Test: `internal/winfs/ntfs/ntfs_windows_test.go`

**Interfaces:**
- Consumes: `ParseBootSector`, `BootSector` (Task 2); `DecodeDataRuns`, `nonResidentDataRuns`, `Extent` (Task 3); `mft.ParseRecord`, `mft.ApplyFixup`, `mft.DetectTimestomp`, `mft.Record`, `mft.Timestamps`, `mft.Verdict` (Task 1); `fsforensic.HasForensicExtension`, `fsforensic.IsSuspiciousName`; `ntfspath.ParentEntry`, `ntfspath.ResolvePath`.
- Produces:
  - `type DeletedEntry struct { FullPath string; FileName string; SI mft.Timestamps; FN mft.Timestamps; Verdict mft.Verdict; RecordNo uint64 }`
  - `var ErrUnsupported = errors.New("acceso raw NTFS solo disponible en Windows")`
  - `func ScanDeleted(ctx context.Context, volume string) ([]DeletedEntry, error)` — lee el boot sector, decodifica los extents del `$MFT`, barre todos los registros en streaming y recupera los borrados forenses. Fuera de Windows devuelve `ErrUnsupported`.

- [ ] **Step 1: Escribir el test (integración, con skip)**

```go
//go:build windows

// internal/winfs/ntfs/ntfs_windows_test.go
package ntfs

import (
	"context"
	"testing"
)

// TestScanDeletedIntegration corre solo con acceso raw al volumen (elevación).
// No es determinista: valida forma, no contenido.
func TestScanDeletedIntegration(t *testing.T) {
	entries, err := ScanDeleted(context.Background(), `\\.\C:`)
	if err != nil {
		t.Skipf("MFT raw no accesible (¿sin elevación o volumen no NTFS?): %v", err)
	}
	for _, e := range entries {
		if e.FileName == "" {
			t.Fatalf("entry sin FileName: %+v", e)
		}
		if e.FullPath == "" {
			t.Fatalf("entry sin FullPath: %+v", e)
		}
	}
}

func TestErrUnsupportedDefined(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported no debería ser nil")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/ntfs/`
Expected: FAIL de compilación — `undefined: ScanDeleted`, `undefined: DeletedEntry`, `undefined: ErrUnsupported`.

- [ ] **Step 3: Escribir `ntfs_other.go` (stub no-Windows)**

```go
//go:build !windows

// internal/winfs/ntfs/ntfs_other.go
package ntfs

import (
	"context"
	"errors"

	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
)

// ErrUnsupported se devuelve al intentar acceso raw NTFS fuera de Windows.
var ErrUnsupported = errors.New("acceso raw NTFS solo disponible en Windows")

// DeletedEntry es una entrada borrada recuperada del MFT.
type DeletedEntry struct {
	FullPath string
	FileName string
	SI       winmft.Timestamps
	FN       winmft.Timestamps
	Verdict  winmft.Verdict
	RecordNo uint64
}

// ScanDeleted no está soportado fuera de Windows.
func ScanDeleted(ctx context.Context, volume string) ([]DeletedEntry, error) {
	return nil, ErrUnsupported
}
```

- [ ] **Step 4: Escribir `ntfs_windows.go` (lectura raw real)**

```go
//go:build windows

// internal/winfs/ntfs/ntfs_windows.go
package ntfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
	"github.com/telagem/agent-windows/internal/winfs/ntfspath"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows.
var ErrUnsupported = errors.New("acceso raw NTFS solo disponible en Windows")

// DeletedEntry es una entrada borrada recuperada del MFT.
type DeletedEntry struct {
	FullPath string
	FileName string
	SI       winmft.Timestamps
	FN       winmft.Timestamps
	Verdict  winmft.Verdict
	RecordNo uint64
}

const (
	chunkTarget = 1 << 20 // objetivo ~1 MB por lectura

	// maxRecords acota el barrido ante MFT patológicos/corruptos.
	maxRecords = 8_000_000

	// mftEntryMask aísla el nº de entrada MFT (48 bits bajos) del file reference.
	mftEntryMask = 0x0000FFFFFFFFFFFF
)

// pendingEntry es un borrado candidato cuyo path se resuelve tras completar el mapa de padres.
type pendingEntry struct {
	fileName  string
	parentRef uint64
	si, fn    winmft.Timestamps
	verdict   winmft.Verdict
	recordNo  uint64
}

// ScanDeleted abre el volumen en crudo, ubica el $MFT vía boot sector + data runs,
// barre todos los registros y recupera los borrados (InUse=0) que son forenses.
func ScanDeleted(ctx context.Context, volume string) ([]DeletedEntry, error) {
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

	// 1. Boot sector → geometría.
	sector := make([]byte, 512)
	if err := readAt(h, 0, sector); err != nil {
		return nil, fmt.Errorf("leer boot sector: %w", err)
	}
	boot, err := ParseBootSector(sector)
	if err != nil {
		return nil, err
	}

	// 2. Registro 0 ($MFT) → data runs de su $DATA.
	rec0 := make([]byte, boot.BytesPerRecord)
	if err := readAt(h, int64(boot.MFTCluster)*int64(boot.ClusterSize), rec0); err != nil {
		return nil, fmt.Errorf("leer registro $MFT: %w", err)
	}
	fixed, err := winmft.ApplyFixup(rec0)
	if err != nil {
		return nil, fmt.Errorf("fixup del $MFT: %w", err)
	}
	runBytes, err := nonResidentDataRuns(fixed)
	if err != nil {
		return nil, err
	}
	extents, err := DecodeDataRuns(runBytes)
	if err != nil {
		return nil, err
	}

	// 3. Barrido en streaming a lo largo de los extents.
	parentMap := make(map[uint64]ntfspath.ParentEntry)
	var pending []pendingEntry

	recSize := boot.BytesPerRecord
	recsPerChunk := chunkTarget / recSize
	if recsPerChunk == 0 {
		recsPerChunk = 1
	}
	readSize := recsPerChunk * recSize
	buf := make([]byte, readSize)
	carry := make([]byte, 0, recSize) // sobrante de registro que cruza un límite de lectura
	var ordinal uint64

	process := func(recBuf []byte, ord uint64) {
		rec, err := winmft.ParseRecord(recBuf)
		if err != nil {
			return // slot inválido, nunca usado o basura: se salta en silencio
		}
		seq := binary.LittleEndian.Uint16(recBuf[0x10:0x12])
		ownRef := uint64(seq)<<48 | (ord & mftEntryMask)

		// Directorios vivos alimentan el mapa de padres para reconstruir rutas.
		if rec.InUse && rec.IsDir && rec.HasFN {
			parentMap[ownRef] = ntfspath.ParentEntry{Name: rec.FileName, ParentRef: rec.ParentRef}
			return
		}
		// Candidatos: borrados, con nombre, forenses.
		if rec.InUse || !rec.HasFN {
			return
		}
		if !fsforensic.HasForensicExtension(rec.FileName) && !fsforensic.IsSuspiciousName(rec.FileName) {
			return
		}
		pending = append(pending, pendingEntry{
			fileName:  rec.FileName,
			parentRef: rec.ParentRef,
			si:        rec.SI,
			fn:        rec.FN,
			verdict:   winmft.DetectTimestomp(rec.SI, rec.FN),
			recordNo:  ord,
		})
	}

	finish := func() []DeletedEntry {
		out := make([]DeletedEntry, 0, len(pending))
		for _, p := range pending {
			out = append(out, DeletedEntry{
				FullPath: ntfspath.ResolvePath(parentMap, p.parentRef, p.fileName),
				FileName: p.fileName,
				SI:       p.si,
				FN:       p.fn,
				Verdict:  p.verdict,
				RecordNo: p.recordNo,
			})
		}
		return out
	}

scan:
	for _, ext := range extents {
		extentBytes := int64(ext.Length) * int64(boot.ClusterSize)
		diskOff := int64(ext.StartLCN) * int64(boot.ClusterSize)
		for pos := int64(0); pos < extentBytes; {
			select {
			case <-ctx.Done():
				return finish(), ctx.Err()
			default:
			}
			toRead := int64(readSize)
			if rem := extentBytes - pos; rem < toRead {
				toRead = rem
			}
			if err := readAt(h, diskOff+pos, buf[:toRead]); err != nil {
				return finish(), fmt.Errorf("leer MFT en offset %d: %w", diskOff+pos, err)
			}
			pos += toRead

			// Combinar el sobrante del bloque anterior con lo recién leído.
			var data []byte
			if len(carry) > 0 {
				data = make([]byte, 0, len(carry)+int(toRead))
				data = append(data, carry...)
				data = append(data, buf[:toRead]...)
				carry = carry[:0]
			} else {
				data = buf[:toRead]
			}

			i := 0
			for ; i+recSize <= len(data); i += recSize {
				process(data[i:i+recSize], ordinal)
				ordinal++
				if ordinal >= maxRecords {
					break scan
				}
			}
			if rem := len(data) - i; rem > 0 {
				carry = append(carry[:0], data[i:]...)
			}
		}
	}
	return finish(), nil
}

// readAt lee len(buf) bytes desde offset usando un OVERLAPPED (posición explícita),
// lo que permite leer por offset en un handle de volumen sincrónico sin mantener
// un puntero de archivo. offset y len(buf) deben estar alineados a sector.
func readAt(h windows.Handle, offset int64, buf []byte) error {
	var ov windows.Overlapped
	ov.Offset = uint32(offset & 0xFFFFFFFF)
	ov.OffsetHigh = uint32(offset >> 32)
	var done uint32
	if err := windows.ReadFile(h, buf, &done, &ov); err != nil {
		return err
	}
	if int(done) != len(buf) {
		return fmt.Errorf("lectura corta: %d de %d bytes", done, len(buf))
	}
	return nil
}
```

- [ ] **Step 5: Correr los tests y el build de Windows**

Run: `go test ./internal/winfs/ntfs/`
Expected: PASS (el test de integración hace SKIP si no hay elevación / volumen no NTFS).
Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./internal/winfs/ntfs/`
Expected: compila sin errores.
Run: `GOOS=windows GOARCH=amd64 go vet ./internal/winfs/ntfs/`
Expected: sin advertencias.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/ntfs/ntfs_windows.go internal/winfs/ntfs/ntfs_other.go internal/winfs/ntfs/ntfs_windows_test.go
git commit -m "feat: barrido raw del MFT y recuperación de entradas borradas"
```

---

### Task 5: Colector de borrados y registro en el entrypoint

**Files:**
- Create: `internal/collector/deleted/deleted.go`
- Test: `internal/collector/deleted/deleted_test.go`
- Modify: `internal/agent/live_windows.go` (registrar el colector)

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact`, `collector.PriorityDisk` (Fase 1); `ntfs.ScanDeleted`, `ntfs.DeletedEntry` (Task 4).
- Produces:
  - `type Collector struct { Volume string }`
  - `func New() *Collector` — `Volume` default `\\.\C:`.
  - Implementa `Name() string` = `"deleted_entries"`, `Priority() int` = `collector.PriorityDisk`, `Collect(ctx) ([]collector.Artifact, error)`.

- [ ] **Step 1: Escribir el test que falla**

```go
//go:build windows

// internal/collector/deleted/deleted_test.go
package deleted

import (
	"context"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "deleted_entries" {
		t.Fatalf("Name = %q, want deleted_entries", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New()
}

// TestCollectReturnsArtifactsOrError valida que Collect no paniquea y respeta la
// forma del contrato (skip si el volumen raw no es accesible).
func TestCollectReturnsArtifactsOrError(t *testing.T) {
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Skipf("MFT raw no accesible: %v", err)
	}
	for _, a := range arts {
		if a.Type != "deleted_entry" {
			t.Fatalf("Type = %q, want deleted_entry", a.Type)
		}
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/deleted/`
Expected: FAIL de compilación — `undefined: New`.

- [ ] **Step 3: Escribir `deleted.go`**

```go
//go:build windows

// internal/collector/deleted/deleted.go
package deleted

import (
	"context"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/ntfs"
)

// Collector recupera metadatos de archivos borrados del volumen vía lectura raw del MFT.
type Collector struct {
	Volume string
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "deleted_entries" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	entries, err := ntfs.ScanDeleted(ctx, c.Volume)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "deleted_entry",
			Source:    e.FullPath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/deleted/`
Expected: PASS (integración con SKIP si no hay volumen accesible).

- [ ] **Step 5: Registrar el colector en `live_windows.go`**

En `internal/agent/live_windows.go`, agregar al bloque de imports (junto a los otros colectores):
```go
	deletedcol "github.com/telagem/agent-windows/internal/collector/deleted"
```
Y agregar la instancia al slice `collectors`, después de `mftcol.New()`:
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

- [ ] **Step 6: Verificar build completo y todos los tests**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.
Run: `go test ./...`
Expected: PASS (los tests de integración MFT/USN/NTFS hacen SKIP si no hay elevación).

- [ ] **Step 7: Commit**

```bash
git add internal/collector/deleted/ internal/agent/live_windows.go
git commit -m "feat: colector de entradas borradas registrado en el entrypoint live"
```

---

## Notas de cierre

- Con esta sub-fase se completa la Fase 3B. El paquete `ntfs` deja disponible el acceso raw (boot sector + data runs + lectura por sector) para futuras necesidades forenses.
- **Fuera de alcance** (posible trabajo futuro): carving de contenido de archivos borrados (excluido por el invariante de privacidad), barrido de `$MFTMirr`/`$LogFile`/`$UsnJrnl:$J`, integración con snapshots VSS, y volúmenes distintos de `C:`.
