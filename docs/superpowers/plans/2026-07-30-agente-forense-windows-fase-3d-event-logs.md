# Fase 3D — Event Logs (.evtx) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agregar un colector de Event Logs que reconstruye timeline de sesión, detecta borrado de logs y manipulación de bajo nivel de los `.evtx`, y cruza eventos `7045`/TaskScheduler contra el estado actual del registro.

**Architecture:** Parser EVTX puro híbrido en `winfs/evtx` (framing + CRC + señales de tampering reales; BinXML pragmático scopeado a una substitution-array co-diseñada con un builder sintético). Un adapter `collector/eventlog` parsea tres logs, reutiliza los parsers puros `winfs/services` y `winfs/scheduler` para el estado actual, corre una función pura `CrossCheck`, y emite Artifacts. Cero acoplamiento entre colectores; el runner no se toca.

**Tech Stack:** Go (stdlib + `golang.org/x/sys/windows`), `hash/crc32` (IEEE), paquetes internos `wintext`, `wintime`, `reghive`, `winfs/services`, `winfs/scheduler`.

## Global Constraints

- Target `GOOS=windows GOARCH=amd64`, sin CGO (`CGO_ENABLED=0`). El parser EVTX es puro Go, sin `wevtapi`.
- Runtime solo stdlib + `golang.org/x/sys`. Sin dependencias externas nuevas.
- Un colector que falla nunca tumba el escaneo (el `runner` recupera panics y propaga errores).
- Nunca recolectar contenido personal; solo metadatos forenses. Se registran SIDs/usuarios para atribución.
- Código en inglés (identificadores); comentarios y commits en español.
- Tests corren en CI Linux con fixtures sintéticos; nada depende de Windows real ni de `.evtx` reales.
- Los `.evtx` son ilegibles en vivo (lock del servicio EventLog): se leen desde snapshot VSS, con fallback a path en vivo.

## Layout de archivos

```
internal/winfs/evtx/evtx.go            framing: header ELF, chunks 64KB, records, tipos públicos (Task 1)
internal/winfs/evtx/evtx_test.go       (Task 1)
internal/winfs/evtx/evtxtest/builder.go  builder de .evtx sintéticos (Task 1)
internal/winfs/evtx/tamper.go          señales: gap record-id, CRC inválido, dirty/full, truncado (Task 2)
internal/winfs/evtx/tamper_test.go     (Task 2)
internal/winfs/evtx/binxml.go          decodificador BinXML pragmático → substitution array (Task 3)
internal/winfs/evtx/binxml_test.go     (Task 3)
internal/winfs/evtx/events.go          mapeo posicional substitutions → Fields por EventID (Task 4)
internal/winfs/evtx/events_test.go     (Task 4)
internal/collector/eventlog/correlate.go       CrossCheck puro (Task 5)
internal/collector/eventlog/correlate_test.go   (Task 5)
internal/collector/eventlog/eventlog.go         adapter Collector (Task 6)
internal/collector/eventlog/eventlog_test.go    (Task 6)
internal/agent/live_windows.go         wiring VSS + registro del colector (Task 7)
```

## Formato EVTX co-diseñado (referencia para todo el plan)

El framing es EVTX real. El BinXML es un **subconjunto pragmático** que el `evtxtest.Builder` y el parser comparten byte a byte; contra `.evtx` reales con templates arbitrarios, el parser degrada a `PartialDecode` (comportamiento aprobado en el spec).

**File header (4096 bytes):**
```
[0:8]    "ElfFile\x00"
[8:16]   FirstChunkNumber  u64 (0)
[16:24]  LastChunkNumber   u64 (numChunks-1)
[24:32]  NextRecordId      u64
[32:36]  HeaderSize        u32 (128)
[36:38]  MinorVersion      u16 (1)
[38:40]  MajorVersion      u16 (3)
[40:42]  HeaderBlockSize   u16 (4096)
[42:44]  NumberOfChunks    u16
[44:120] ceros
[120:124] FileFlags        u32 (bit0=dirty, bit1=full)
[124:128] Checksum         u32 = CRC32-IEEE(header[0:120])
[128:4096] ceros
```

**Chunk (65536 bytes), primer chunk en offset 4096:**
```
[0:8]    "ElfChnk\x00"
[8:16]   FirstEventRecordNumber u64 (1)
[16:24]  LastEventRecordNumber  u64
[24:32]  FirstEventRecordId     u64 (= id del primer record)
[32:40]  LastEventRecordId      u64 (= id del último record)
[40:44]  HeaderSize             u32 (128)
[44:48]  LastEventRecordDataOffset u32 (offset relativo al chunk del último record)
[48:52]  FreeSpaceOffset        u32 (offset relativo donde termina el último record)
[52:56]  EventRecordsChecksum   u32 = CRC32-IEEE(chunk[512:FreeSpaceOffset])
[56:120] ceros
[120:124] ceros
[124:128] Checksum              u32 = CRC32-IEEE(chunk[0:120] ++ chunk[128:512])
[128:512] tablas (string/template): ceros en el subset sintético
[512:...] records consecutivos
```

**Event record:**
```
[0:4]    magic 0x2a 0x2a 0x00 0x00
[4:8]    Size u32 (tamaño total del record, múltiplo de 8)
[8:16]   EventRecordId u64
[16:24]  WrittenTime FILETIME u64
[24:Size-4] payload BinXML
[Size-4:Size] Size u32 (copia)
```

**Payload BinXML (subset co-diseñado):**
```
[0]      0x0F  FragmentHeader token
[1]      0x01  major
[2]      0x01  minor
[3]      0x00  flags
[4]      0x0C  TemplateInstance token
[5:9]    substitutionCount u32 (N)
 luego N descriptores, cada uno = valType u8 ++ valLen u16
 luego N valores concatenados (valLen bytes cada uno)
```
Convención: `subs[0]` es SIEMPRE el EventID (valType `TypeUInt16`). `subs[1..]` son los campos por-EventID.
Tipos de value soportados:
```
TypeString   = 0x01  // UTF-16LE, valLen bytes, vía wintext.DecodeUTF16
TypeUInt16   = 0x06  // 2 bytes LE
TypeUInt32   = 0x08  // 4 bytes LE
TypeFileTime = 0x11  // 8 bytes LE, vía wintime.FiletimeToTime
```

---

### Task 1: Framing EVTX + builder sintético

**Files:**
- Create: `internal/winfs/evtx/evtx.go`
- Create: `internal/winfs/evtx/evtxtest/builder.go`
- Test: `internal/winfs/evtx/evtx_test.go`

**Interfaces:**
- Consumes: `wintime.FiletimeToTime(ft uint64) time.Time`.
- Produces:
  - `type SubValue struct { Type uint8; Raw []byte }`
  - `type Record struct { ID uint64; Timestamp time.Time; EventID uint16; Channel string; PartialDecode bool; Subs []SubValue; Fields map[string]string }`
  - `type TamperSignal struct { Kind string; Detail string; RecordID uint64 }`
  - `type Log struct { Records []Record; Tamper []TamperSignal; Dirty bool; Full bool }`
  - `func Open(path, channel string) (*Log, error)`
  - `func parseLog(data []byte, channel string) (*Log, error)` (interno; en Task 1 llena ID/Timestamp/Subs vacíos; EventID/BinXML lo agrega Task 3)
  - Constantes `TypeString=0x01`, `TypeUInt16=0x06`, `TypeUInt32=0x08`, `TypeFileTime=0x11`
  - Builder: `evtxtest.NewBuilder() *Builder`, `func (b *Builder) AddRecord(id uint64, ts time.Time, eventID uint16, subs []Sub) *Builder`, `func (b *Builder) Build() []byte`, y helpers `evtxtest.StringSub(s string) Sub`, `U16Sub(v uint16) Sub`, `U32Sub(v uint32) Sub`, `FileTimeSub(t time.Time) Sub`.

- [ ] **Step 1: Escribir el builder sintético**

`internal/winfs/evtx/evtxtest/builder.go`:
```go
// Package evtxtest arma archivos .evtx sintéticos en memoria para testear el
// parser sin depender de un dump real. Implementa solo el subconjunto de
// BinXML que winfs/evtx decodifica (substitution array co-diseñada).
package evtxtest

import (
	"encoding/binary"
	"hash/crc32"
	"time"
)

// Tipos de value soportados (deben coincidir con winfs/evtx).
const (
	typeString   = 0x01
	typeUInt16   = 0x06
	typeUInt32   = 0x08
	typeFileTime = 0x11
)

// Sub es un valor de substitution tipado.
type Sub struct {
	Type uint8
	Raw  []byte
}

func StringSub(s string) Sub {
	u := utf16le(s)
	return Sub{Type: typeString, Raw: u}
}

func U16Sub(v uint16) Sub {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return Sub{Type: typeUInt16, Raw: b}
}

func U32Sub(v uint32) Sub {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return Sub{Type: typeUInt32, Raw: b}
}

func FileTimeSub(t time.Time) Sub {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, timeToFiletime(t))
	return Sub{Type: typeFileTime, Raw: b}
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// timeToFiletime: inverso de wintime.FiletimeToTime (100ns desde 1601-01-01).
func timeToFiletime(t time.Time) uint64 {
	const epochDiff = 116444736000000000 // 100ns entre 1601 y 1970
	return uint64(t.UnixNano()/100) + epochDiff
}

type rec struct {
	id      uint64
	ts      time.Time
	eventID uint16
	subs    []Sub
}

// Builder arma un .evtx de un solo chunk con los records dados.
type Builder struct {
	recs  []rec
	dirty bool
	full  bool
}

func NewBuilder() *Builder { return &Builder{} }

func (b *Builder) AddRecord(id uint64, ts time.Time, eventID uint16, subs []Sub) *Builder {
	b.recs = append(b.recs, rec{id: id, ts: ts, eventID: eventID, subs: subs})
	return b
}

func (b *Builder) WithDirty() *Builder { b.dirty = true; return b }
func (b *Builder) WithFull() *Builder  { b.full = true; return b }

// binxml arma el payload de un record (FragmentHeader + TemplateInstance +
// substitution array; subs[0] es el EventID).
func binxml(eventID uint16, subs []Sub) []byte {
	all := append([]Sub{{Type: typeUInt16, Raw: u16(eventID)}}, subs...)
	out := []byte{0x0F, 0x01, 0x01, 0x00, 0x0C}
	out = append(out, u32(uint32(len(all)))...)
	for _, s := range all {
		out = append(out, s.Type)
		out = append(out, u16(uint16(len(s.Raw)))...)
	}
	for _, s := range all {
		out = append(out, s.Raw...)
	}
	return out
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

// Build devuelve el archivo .evtx completo (file header + un chunk).
func (b *Builder) Build() []byte {
	chunk := make([]byte, 65536)
	copy(chunk[0:8], "ElfChnk\x00")

	off := 512
	var firstID, lastID, lastOff uint64
	for i, r := range b.recs {
		payload := binxml(r.eventID, r.subs)
		size := 24 + len(payload) + 4
		if pad := size % 8; pad != 0 {
			size += 8 - pad
			payload = append(payload, make([]byte, 8-pad)...)
		}
		copy(chunk[off:off+4], []byte{0x2a, 0x2a, 0x00, 0x00})
		binary.LittleEndian.PutUint32(chunk[off+4:], uint32(size))
		binary.LittleEndian.PutUint64(chunk[off+8:], r.id)
		binary.LittleEndian.PutUint64(chunk[off+16:], timeToFiletime(r.ts))
		copy(chunk[off+24:], payload)
		binary.LittleEndian.PutUint32(chunk[off+size-4:], uint32(size))
		if i == 0 {
			firstID = r.id
		}
		lastID = r.id
		lastOff = uint64(off)
		off += size
	}
	freeSpace := uint32(off)

	binary.LittleEndian.PutUint64(chunk[8:], 1)
	binary.LittleEndian.PutUint64(chunk[16:], uint64(len(b.recs)))
	binary.LittleEndian.PutUint64(chunk[24:], firstID)
	binary.LittleEndian.PutUint64(chunk[32:], lastID)
	binary.LittleEndian.PutUint32(chunk[40:], 128)
	binary.LittleEndian.PutUint32(chunk[44:], uint32(lastOff))
	binary.LittleEndian.PutUint32(chunk[48:], freeSpace)
	binary.LittleEndian.PutUint32(chunk[52:], crc32.ChecksumIEEE(chunk[512:freeSpace]))
	h := crc32.NewIEEE()
	h.Write(chunk[0:120])
	h.Write(chunk[128:512])
	binary.LittleEndian.PutUint32(chunk[124:], h.Sum32())

	header := make([]byte, 4096)
	copy(header[0:8], "ElfFile\x00")
	binary.LittleEndian.PutUint64(header[8:], 0)
	binary.LittleEndian.PutUint64(header[16:], 0)
	binary.LittleEndian.PutUint64(header[24:], lastID+1)
	binary.LittleEndian.PutUint32(header[32:], 128)
	binary.LittleEndian.PutUint16(header[36:], 1)
	binary.LittleEndian.PutUint16(header[38:], 3)
	binary.LittleEndian.PutUint16(header[40:], 4096)
	binary.LittleEndian.PutUint16(header[42:], 1)
	var flags uint32
	if b.dirty {
		flags |= 0x1
	}
	if b.full {
		flags |= 0x2
	}
	binary.LittleEndian.PutUint32(header[120:], flags)
	binary.LittleEndian.PutUint32(header[124:], crc32.ChecksumIEEE(header[0:120]))

	return append(header, chunk...)
}
```

- [ ] **Step 2: Escribir el test de framing (falla)**

`internal/winfs/evtx/evtx_test.go`:
```go
package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestParseLogReadsRecords(t *testing.T) {
	ts := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{evtxtest.StringSub("mirko")}).
		AddRecord(2, ts.Add(time.Minute), 4634, []evtxtest.Sub{evtxtest.StringSub("mirko")}).
		Build()

	log, err := parseLog(data, "Security")
	if err != nil {
		t.Fatalf("parseLog: %v", err)
	}
	if len(log.Records) != 2 {
		t.Fatalf("esperaba 2 records, obtuve %d", len(log.Records))
	}
	if log.Records[0].ID != 1 || log.Records[1].ID != 2 {
		t.Fatalf("ids inesperados: %d, %d", log.Records[0].ID, log.Records[1].ID)
	}
	if !log.Records[0].Timestamp.Equal(ts) {
		t.Fatalf("timestamp inesperado: %v", log.Records[0].Timestamp)
	}
	if log.Records[0].Channel != "Security" {
		t.Fatalf("channel inesperado: %q", log.Records[0].Channel)
	}
}
```

- [ ] **Step 3: Correr el test — debe fallar**

Run: `go test ./internal/winfs/evtx/ -run TestParseLogReadsRecords`
Expected: FAIL (paquete/símbolos inexistentes).

- [ ] **Step 4: Implementar el framing**

`internal/winfs/evtx/evtx.go`:
```go
// Package evtx parsea archivos Windows Event Log (.evtx) de forma pura, sin
// depender del servicio EventLog. Implementa el framing real (header ELF,
// chunks, records, CRC32) y un decodificador BinXML pragmático scopeado a los
// EventIDs forenses; ante estructuras no soportadas degrada a PartialDecode.
package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Tipos de value BinXML soportados.
const (
	TypeString   = 0x01
	TypeUInt16   = 0x06
	TypeUInt32   = 0x08
	TypeFileTime = 0x11
)

// SubValue es un valor de la substitution array de un record.
type SubValue struct {
	Type uint8
	Raw  []byte
}

// Record es un evento parseado.
type Record struct {
	ID            uint64
	Timestamp     time.Time
	EventID       uint16
	Channel       string
	PartialDecode bool
	Subs          []SubValue
	Fields        map[string]string
}

// TamperSignal es una anomalía estructural del archivo.
type TamperSignal struct {
	Kind     string
	Detail   string
	RecordID uint64
}

// Log es el resultado de parsear un .evtx completo.
type Log struct {
	Records []Record
	Tamper  []TamperSignal
	Dirty   bool
	Full    bool
}

const chunkSize = 65536

// Open lee y parsea un archivo .evtx, etiquetando cada record con channel.
func Open(path, channel string) (*Log, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseLog(data, channel)
}

func parseLog(data []byte, channel string) (*Log, error) {
	if len(data) < 4096 || string(data[0:8]) != "ElfFile\x00" {
		return nil, errors.New("evtx: header ElfFile inválido")
	}
	log := &Log{}
	flags := binary.LittleEndian.Uint32(data[120:124])
	log.Dirty = flags&0x1 != 0
	log.Full = flags&0x2 != 0

	for off := 4096; off+chunkSize <= len(data); off += chunkSize {
		chunk := data[off : off+chunkSize]
		if string(chunk[0:8]) != "ElfChnk\x00" {
			break
		}
		parseChunkRecords(chunk, channel, log)
	}
	return log, nil
}

// parseChunkRecords extrae los records de un chunk (sin validar CRC ni
// decodificar BinXML todavía: eso lo agregan Task 2 y Task 3).
func parseChunkRecords(chunk []byte, channel string, log *Log) {
	freeSpace := binary.LittleEndian.Uint32(chunk[48:52])
	for off := uint32(512); off+24 <= freeSpace && off+24 <= uint32(len(chunk)); {
		if binary.LittleEndian.Uint32(chunk[off:off+4]) != 0x00002a2a {
			break
		}
		size := binary.LittleEndian.Uint32(chunk[off+4 : off+8])
		if size < 32 || off+size > uint32(len(chunk)) {
			break
		}
		r := Record{
			ID:        binary.LittleEndian.Uint64(chunk[off+8 : off+16]),
			Timestamp: wintime.FiletimeToTime(binary.LittleEndian.Uint64(chunk[off+16 : off+24])),
			Channel:   channel,
		}
		log.Records = append(log.Records, r)
		off += size
	}
}
```

- [ ] **Step 5: Correr el test — debe pasar**

Run: `go test ./internal/winfs/evtx/ -run TestParseLogReadsRecords`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/evtx/evtx.go internal/winfs/evtx/evtx_test.go internal/winfs/evtx/evtxtest/builder.go
git commit -m "feat: framing EVTX puro y builder de .evtx sinteticos

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Señales de tampering

**Files:**
- Create: `internal/winfs/evtx/tamper.go`
- Test: `internal/winfs/evtx/tamper_test.go`
- Modify: `internal/winfs/evtx/evtx.go` (llamar a la detección desde `parseLog`/`parseChunkRecords`)

**Interfaces:**
- Consumes: `Log`, `TamperSignal`, `parseLog` (Task 1).
- Produces: señales pobladas en `Log.Tamper` con `Kind` ∈ {`chunk_crc_invalid`, `record_id_gap`, `dirty_flag`, `full_flag`, `truncated`}.

- [ ] **Step 1: Escribir el test (falla)**

`internal/winfs/evtx/tamper_test.go`:
```go
package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func hasTamper(log *Log, kind string) bool {
	for _, t := range log.Tamper {
		if t.Kind == kind {
			return true
		}
	}
	return false
}

func TestTamperRecordIDGap(t *testing.T) {
	ts := time.Now().UTC()
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, nil).
		AddRecord(5, ts, 4624, nil). // salto 1 -> 5
		Build()
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "record_id_gap") {
		t.Fatal("esperaba señal record_id_gap")
	}
}

func TestTamperDirtyFlag(t *testing.T) {
	data := evtxtest.NewBuilder().WithDirty().AddRecord(1, time.Now().UTC(), 4624, nil).Build()
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "dirty_flag") {
		t.Fatal("esperaba señal dirty_flag")
	}
}

func TestTamperChunkCRCInvalid(t *testing.T) {
	data := evtxtest.NewBuilder().AddRecord(1, time.Now().UTC(), 4624, nil).Build()
	data[4096+512+8]++ // corromper datos del chunk sin recomputar CRC
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "chunk_crc_invalid") {
		t.Fatal("esperaba señal chunk_crc_invalid")
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/winfs/evtx/ -run TestTamper`
Expected: FAIL.

- [ ] **Step 3: Implementar la detección**

`internal/winfs/evtx/tamper.go`:
```go
package evtx

import (
	"fmt"
	"hash/crc32"
)

// checkChunkCRC valida el checksum del header del chunk (bytes 0:120 ++
// 128:512) y el de los records (512:freeSpace). Cualquier mismatch es señal
// de manipulación directa del archivo.
func checkChunkCRC(chunk []byte, log *Log) {
	freeSpace := readU32(chunk, 48)
	if freeSpace < 512 || freeSpace > uint32(len(chunk)) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "truncated", Detail: "freeSpaceOffset fuera de rango"})
		return
	}
	h := crc32.NewIEEE()
	h.Write(chunk[0:120])
	h.Write(chunk[128:512])
	if h.Sum32() != readU32(chunk, 124) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "chunk_crc_invalid", Detail: "header checksum"})
	}
	if crc32.ChecksumIEEE(chunk[512:freeSpace]) != readU32(chunk, 52) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "chunk_crc_invalid", Detail: "records checksum"})
	}
}

// checkRecordGaps detecta saltos en el id monotónico de record: evidencia de
// registros borrados. Debe llamarse una vez con todos los records en orden.
func checkRecordGaps(records []Record, log *Log) {
	for i := 1; i < len(records); i++ {
		if records[i].ID > records[i-1].ID+1 {
			log.Tamper = append(log.Tamper, TamperSignal{
				Kind:     "record_id_gap",
				Detail:   fmt.Sprintf("salto de %d a %d", records[i-1].ID, records[i].ID),
				RecordID: records[i].ID,
			})
		}
	}
}

func checkFileFlags(log *Log) {
	if log.Dirty {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "dirty_flag", Detail: "archivo cerrado sucio"})
	}
	if log.Full {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "full_flag", Detail: "archivo marcado lleno"})
	}
}

func readU32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}
```

- [ ] **Step 4: Cablear la detección en `parseLog`**

En `internal/winfs/evtx/evtx.go`, dentro de `parseLog`, después de setear `Dirty`/`Full` y antes del loop de chunks agregar `checkFileFlags(log)`; dentro del loop, después de `if string(chunk[0:8]) != "ElfChnk\x00" { break }` agregar `checkChunkCRC(chunk, log)`; y después del loop de chunks agregar `checkRecordGaps(log.Records, log)`. El bloque queda:
```go
	checkFileFlags(log)
	for off := 4096; off+chunkSize <= len(data); off += chunkSize {
		chunk := data[off : off+chunkSize]
		if string(chunk[0:8]) != "ElfChnk\x00" {
			break
		}
		checkChunkCRC(chunk, log)
		parseChunkRecords(chunk, channel, log)
	}
	checkRecordGaps(log.Records, log)
	return log, nil
```

- [ ] **Step 5: Correr los tests — deben pasar**

Run: `go test ./internal/winfs/evtx/`
Expected: PASS (Task 1 y Task 2).

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/evtx/tamper.go internal/winfs/evtx/tamper_test.go internal/winfs/evtx/evtx.go
git commit -m "feat: senales de tampering EVTX (CRC, gaps de record-id, dirty/full)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Decodificador BinXML (substitution array)

**Files:**
- Create: `internal/winfs/evtx/binxml.go`
- Test: `internal/winfs/evtx/binxml_test.go`
- Modify: `internal/winfs/evtx/evtx.go` (poblar `EventID`/`Subs`/`PartialDecode` en `parseChunkRecords`)

**Interfaces:**
- Consumes: `SubValue`, constantes de tipo (Task 1).
- Produces: `func decodeBinXML(payload []byte) (eventID uint16, subs []SubValue, partial bool)`.

- [ ] **Step 1: Escribir el test (falla)**

`internal/winfs/evtx/binxml_test.go`:
```go
package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestDecodeBinXMLReadsSubstitutions(t *testing.T) {
	ts := time.Now().UTC()
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{
			evtxtest.StringSub("mirko"),
			evtxtest.U32Sub(10), // LogonType RDP
		}).
		Build()
	log, _ := parseLog(data, "Security")
	r := log.Records[0]
	if r.EventID != 4624 {
		t.Fatalf("EventID esperado 4624, obtuve %d", r.EventID)
	}
	if r.PartialDecode {
		t.Fatal("no debería ser PartialDecode")
	}
	// subs[0] es el EventID; subs[1..] los campos.
	if len(r.Subs) != 3 {
		t.Fatalf("esperaba 3 subs, obtuve %d", len(r.Subs))
	}
	if r.Subs[1].Type != TypeString {
		t.Fatalf("sub[1] debería ser string, tipo %#x", r.Subs[1].Type)
	}
}

func TestDecodeBinXMLPartialOnGarbage(t *testing.T) {
	_, _, partial := decodeBinXML([]byte{0xFF, 0xFF, 0xFF})
	if !partial {
		t.Fatal("payload basura debería marcar partial")
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/winfs/evtx/ -run TestDecodeBinXML`
Expected: FAIL (`decodeBinXML` no existe; `EventID` sin poblar).

- [ ] **Step 3: Implementar el decodificador**

`internal/winfs/evtx/binxml.go`:
```go
package evtx

import "encoding/binary"

const (
	tokenFragmentHeader  = 0x0F
	tokenTemplateInstance = 0x0C
)

// decodeBinXML lee el subconjunto co-diseñado: FragmentHeader +
// TemplateInstance + substitution array. subs[0] es el EventID (UInt16).
// Ante cualquier estructura no reconocida devuelve partial=true y lo que
// haya podido leer (degradación graceful).
func decodeBinXML(payload []byte) (eventID uint16, subs []SubValue, partial bool) {
	if len(payload) < 5 || payload[0] != tokenFragmentHeader || payload[4] != tokenTemplateInstance {
		return 0, nil, true
	}
	p := 5
	if p+4 > len(payload) {
		return 0, nil, true
	}
	count := int(binary.LittleEndian.Uint32(payload[p : p+4]))
	p += 4
	if count < 1 || count > 256 {
		return 0, nil, true
	}
	type desc struct {
		typ uint8
		ln  int
	}
	descs := make([]desc, 0, count)
	for i := 0; i < count; i++ {
		if p+3 > len(payload) {
			return 0, nil, true
		}
		typ := payload[p]
		ln := int(binary.LittleEndian.Uint16(payload[p+1 : p+3]))
		descs = append(descs, desc{typ: typ, ln: ln})
		p += 3
	}
	values := make([]SubValue, 0, count)
	for _, d := range descs {
		if p+d.ln > len(payload) {
			return 0, nil, true
		}
		values = append(values, SubValue{Type: d.typ, Raw: payload[p : p+d.ln]})
		p += d.ln
	}
	if values[0].Type != TypeUInt16 || len(values[0].Raw) < 2 {
		return 0, values, true
	}
	return binary.LittleEndian.Uint16(values[0].Raw), values, false
}
```

- [ ] **Step 4: Poblar el record en `parseChunkRecords`**

En `internal/winfs/evtx/evtx.go`, dentro de `parseChunkRecords`, después de construir `r` con ID/Timestamp/Channel y antes de `log.Records = append(...)`, decodificar el BinXML del record (offset `off+24` hasta `off+size-4`):
```go
		payload := chunk[off+24 : off+size-4]
		eventID, subs, partial := decodeBinXML(payload)
		r.EventID = eventID
		r.Subs = subs
		r.PartialDecode = partial
```

- [ ] **Step 5: Correr los tests — deben pasar**

Run: `go test ./internal/winfs/evtx/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/evtx/binxml.go internal/winfs/evtx/binxml_test.go internal/winfs/evtx/evtx.go
git commit -m "feat: decodificador BinXML pragmatico con substitution array y degradacion graceful

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Mapeo de EventIDs a Fields

**Files:**
- Create: `internal/winfs/evtx/events.go`
- Test: `internal/winfs/evtx/events_test.go`
- Modify: `internal/winfs/evtx/evtx.go` (poblar `Record.Fields` tras decodificar)

**Interfaces:**
- Consumes: `Record`, `SubValue`, constantes de tipo (Tasks 1 y 3), `wintext.DecodeUTF16`.
- Produces: `func fieldsFor(eventID uint16, subs []SubValue) map[string]string`. Nombres de campo por EventID:
  - `4624`: `TargetUserName`(subs[1] str), `LogonType`(subs[2] u32)
  - `4634`: `TargetUserName`(subs[1] str)
  - `1102`: `SubjectUserName`(subs[1] str)
  - `104`: `Channel`(subs[1] str), `SubjectUserName`(subs[2] str)
  - `7045`: `ServiceName`(subs[1] str), `ImagePath`(subs[2] str)
  - `106`/`140`/`141`: `TaskName`(subs[1] str)
  - `6005`/`6006`/`6008`: sin campos (solo timestamp).

- [ ] **Step 1: Escribir el test (falla)**

`internal/winfs/evtx/events_test.go`:
```go
package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestFieldsForLogon(t *testing.T) {
	data := evtxtest.NewBuilder().
		AddRecord(1, time.Now().UTC(), 4624, []evtxtest.Sub{
			evtxtest.StringSub("mirko"),
			evtxtest.U32Sub(10),
		}).Build()
	log, _ := parseLog(data, "Security")
	f := log.Records[0].Fields
	if f["TargetUserName"] != "mirko" {
		t.Fatalf("TargetUserName inesperado: %q", f["TargetUserName"])
	}
	if f["LogonType"] != "10" {
		t.Fatalf("LogonType inesperado: %q", f["LogonType"])
	}
}

func TestFieldsForServiceInstall(t *testing.T) {
	data := evtxtest.NewBuilder().
		AddRecord(1, time.Now().UTC(), 7045, []evtxtest.Sub{
			evtxtest.StringSub("EvilDrv"),
			evtxtest.StringSub(`C:\Temp\evil.sys`),
		}).Build()
	log, _ := parseLog(data, "System")
	f := log.Records[0].Fields
	if f["ServiceName"] != "EvilDrv" || f["ImagePath"] != `C:\Temp\evil.sys` {
		t.Fatalf("campos 7045 inesperados: %+v", f)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/winfs/evtx/ -run TestFieldsFor`
Expected: FAIL (`Fields` nil).

- [ ] **Step 3: Implementar el mapeo**

`internal/winfs/evtx/events.go`:
```go
package evtx

import (
	"strconv"

	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// fieldMap describe qué nombre y cómo interpretar cada substitution por
// posición (índice en subs, donde subs[0] es el EventID).
type fieldSpec struct {
	index int
	name  string
}

var eventFields = map[uint16][]fieldSpec{
	4624: {{1, "TargetUserName"}, {2, "LogonType"}},
	4634: {{1, "TargetUserName"}},
	1102: {{1, "SubjectUserName"}},
	104:  {{1, "Channel"}, {2, "SubjectUserName"}},
	7045: {{1, "ServiceName"}, {2, "ImagePath"}},
	106:  {{1, "TaskName"}},
	140:  {{1, "TaskName"}},
	141:  {{1, "TaskName"}},
}

// fieldsFor traduce las substitutions posicionales a un mapa nombre->valor
// según el EventID. Un índice fuera de rango se omite sin fallar.
func fieldsFor(eventID uint16, subs []SubValue) map[string]string {
	specs, ok := eventFields[eventID]
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		if s.index >= len(subs) {
			continue
		}
		out[s.name] = renderValue(subs[s.index])
	}
	return out
}

// renderValue convierte un SubValue a string legible según su tipo.
func renderValue(v SubValue) string {
	switch v.Type {
	case TypeString:
		return wintext.DecodeUTF16(v.Raw)
	case TypeUInt16:
		if len(v.Raw) >= 2 {
			return strconv.FormatUint(uint64(v.Raw[0])|uint64(v.Raw[1])<<8, 10)
		}
	case TypeUInt32:
		if len(v.Raw) >= 4 {
			return strconv.FormatUint(uint64(readU32(v.Raw, 0)), 10)
		}
	}
	return ""
}
```

- [ ] **Step 4: Poblar `Fields` en `parseChunkRecords`**

En `internal/winfs/evtx/evtx.go`, dentro de `parseChunkRecords`, después de setear `r.EventID/r.Subs/r.PartialDecode` agregar:
```go
		r.Fields = fieldsFor(eventID, subs)
```

- [ ] **Step 5: Correr los tests — deben pasar**

Run: `go test ./internal/winfs/evtx/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/evtx/events.go internal/winfs/evtx/events_test.go internal/winfs/evtx/evtx.go
git commit -m "feat: mapeo posicional de EventIDs forenses a campos nombrados

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Correlación pura (CrossCheck)

**Files:**
- Create: `internal/collector/eventlog/correlate.go`
- Test: `internal/collector/eventlog/correlate_test.go`

**Interfaces:**
- Consumes: `winservices.DriverService` (`{Name, ImagePath string; Type, Start uint32}`), `winscheduler.CachedTask` (`{RelPath, ID string}`).
- Produces:
  - `type InstallEvent struct { ServiceName, ImagePath string }`
  - `type TaskEvent struct { Action, TaskName string }` (`Action` ∈ {`register`, `update`, `delete`})
  - `type Desync struct { Kind, Subject, Note string }`
  - `func CrossCheck(installs []InstallEvent, currentServices []winservices.DriverService, taskEvents []TaskEvent, currentTasks []winscheduler.CachedTask, logsCleared bool) []Desync`

- [ ] **Step 1: Escribir el test (falla)**

`internal/collector/eventlog/correlate_test.go`:
```go
package eventlog

import (
	"testing"

	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

func hasDesync(ds []Desync, kind, subject string) bool {
	for _, d := range ds {
		if d.Kind == kind && d.Subject == subject {
			return true
		}
	}
	return false
}

func TestServiceWithoutInstallLog(t *testing.T) {
	current := []winservices.DriverService{{Name: "EvilDrv", ImagePath: `C:\Temp\evil.sys`}}
	ds := CrossCheck(nil, current, nil, nil, false)
	if !hasDesync(ds, "service_no_install_log", "EvilDrv") {
		t.Fatalf("esperaba service_no_install_log para EvilDrv, obtuve %+v", ds)
	}
}

func TestServiceInstalledThenRemoved(t *testing.T) {
	installs := []InstallEvent{{ServiceName: "EvilDrv", ImagePath: `C:\Temp\evil.sys`}}
	ds := CrossCheck(installs, nil, nil, nil, false)
	if !hasDesync(ds, "service_installed_then_removed", "EvilDrv") {
		t.Fatalf("esperaba service_installed_then_removed, obtuve %+v", ds)
	}
}

func TestTaskDeleteDesync(t *testing.T) {
	events := []TaskEvent{{Action: "delete", TaskName: "Updater"}}
	current := []winscheduler.CachedTask{{RelPath: "Updater", ID: "{GUID}"}}
	ds := CrossCheck(nil, nil, events, current, false)
	if !hasDesync(ds, "task_delete_desync", "Updater") {
		t.Fatalf("esperaba task_delete_desync, obtuve %+v", ds)
	}
}

func TestLogsClearedAnnotation(t *testing.T) {
	current := []winservices.DriverService{{Name: "EvilDrv"}}
	ds := CrossCheck(nil, current, nil, nil, true)
	if len(ds) == 0 || ds[0].Note == "" {
		t.Fatalf("con logsCleared debería anotarse Note, obtuve %+v", ds)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/collector/eventlog/ -run 'TestService|TestTask|TestLogs'`
Expected: FAIL.

- [ ] **Step 3: Implementar la correlación**

`internal/collector/eventlog/correlate.go`:
```go
// Package eventlog correlaciona Event Logs (.evtx) contra el estado actual
// del registro para detectar desincronizaciones (evidencia de borrado de
// logs o inyección manual).
package eventlog

import (
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// InstallEvent es un evento 7045 (instalación de servicio) parseado del EVTX.
type InstallEvent struct {
	ServiceName string
	ImagePath   string
}

// TaskEvent es un evento 106/140/141 de TaskScheduler/Operational.
type TaskEvent struct {
	Action   string // "register", "update", "delete"
	TaskName string
}

// Desync es una discrepancia entre logs y estado actual.
type Desync struct {
	Kind    string
	Subject string
	Note    string
}

const clearedNote = "esperable por borrado de logs"

// CrossCheck aplica las reglas de desincronización. currentServices y
// currentTasks ya vienen filtrados por el colector a la superficie no
// estándar (drivers no-Microsoft, tareas fuera de Microsoft\) para no
// generar ruido con miles de artefactos legítimos del sistema.
func CrossCheck(
	installs []InstallEvent,
	currentServices []winservices.DriverService,
	taskEvents []TaskEvent,
	currentTasks []winscheduler.CachedTask,
	logsCleared bool,
) []Desync {
	var out []Desync

	for _, s := range currentServices {
		if !hasInstall(installs, s.Name) {
			out = append(out, Desync{Kind: "service_no_install_log", Subject: s.Name})
		}
	}
	for _, in := range installs {
		if !hasService(currentServices, in.ServiceName) {
			out = append(out, Desync{Kind: "service_installed_then_removed", Subject: in.ServiceName})
		}
	}
	for _, t := range currentTasks {
		if !hasTaskEvent(taskEvents, "register", t.RelPath) {
			out = append(out, Desync{Kind: "task_no_register_log", Subject: t.RelPath})
		}
	}
	for _, e := range taskEvents {
		if e.Action == "delete" && hasTask(currentTasks, e.TaskName) {
			out = append(out, Desync{Kind: "task_delete_desync", Subject: e.TaskName})
		}
	}

	if logsCleared {
		for i := range out {
			out[i].Note = clearedNote
		}
	}
	return out
}

func hasInstall(installs []InstallEvent, name string) bool {
	for _, in := range installs {
		if in.ServiceName == name {
			return true
		}
	}
	return false
}

func hasService(services []winservices.DriverService, name string) bool {
	for _, s := range services {
		if s.Name == name {
			return true
		}
	}
	return false
}

func hasTaskEvent(events []TaskEvent, action, relPath string) bool {
	for _, e := range events {
		if e.Action == action && taskMatches(relPath, e.TaskName) {
			return true
		}
	}
	return false
}

func hasTask(tasks []winscheduler.CachedTask, name string) bool {
	for _, t := range tasks {
		if taskMatches(t.RelPath, name) {
			return true
		}
	}
	return false
}

// taskMatches compara por elemento final de la ruta: los eventos suelen dar
// "\Updater" mientras el registro da "Updater" o "Foo\Updater".
func taskMatches(relPath, name string) bool {
	return lastElem(relPath) == lastElem(name)
}

func lastElem(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
```

- [ ] **Step 4: Correr los tests — deben pasar**

Run: `go test ./internal/collector/eventlog/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/eventlog/correlate.go internal/collector/eventlog/correlate_test.go
git commit -m "feat: correlacion pura de eventos EVTX contra estado del registro (7045, tareas)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Adapter del colector

**Files:**
- Create: `internal/collector/eventlog/eventlog.go`
- Test: `internal/collector/eventlog/eventlog_test.go`

**Interfaces:**
- Consumes: `collector.Artifact`/`collector.PriorityDisk`, `evtx.Open`/`evtx.Log`/`evtx.Record`, `reghive.Open`, `winservices.ParseServices`/`IsNonMicrosoftDriver`, `winscheduler.WalkTaskCacheTree`, `CrossCheck` y tipos de Task 5.
- Produces: `func New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector`; `Collect` emite Artifacts de `Type` ∈ {`eventlog.session_timeline`, `eventlog.log_cleared`, `eventlog.tamper_signal`, `eventlog.desync`}.

- [ ] **Step 1: Escribir el test (falla)**

Los `.evtx` de prueba se generan con `evtxtest.Builder` y se escriben a `t.TempDir()`. El estado actual (hives) no es necesario para este test: se pasan paths vacíos y el colector debe degradar sin fallar. Este test valida la extracción desde EVTX (timeline, clear, tamper).

`internal/collector/eventlog/eventlog_test.go`:
```go
package eventlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func writeEvtx(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestCollectEmitsTimelineAndClear(t *testing.T) {
	ts := time.Now().UTC()
	sec := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{evtxtest.StringSub("mirko"), evtxtest.U32Sub(2)}).
		AddRecord(2, ts.Add(time.Minute), 1102, []evtxtest.Sub{evtxtest.StringSub("attacker")}).
		Build()
	secPath := writeEvtx(t, "Security.evtx", sec)

	c := New(secPath, "", "", "", "")
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var timeline, cleared int
	for _, a := range arts {
		switch a.Type {
		case "eventlog.session_timeline":
			timeline++
		case "eventlog.log_cleared":
			cleared++
		}
	}
	if timeline == 0 {
		t.Fatal("esperaba al menos un artifact session_timeline")
	}
	if cleared != 1 {
		t.Fatalf("esperaba 1 log_cleared, obtuve %d", cleared)
	}
}
```

- [ ] **Step 2: Correr el test — debe fallar**

Run: `go test ./internal/collector/eventlog/ -run TestCollect`
Expected: FAIL.

- [ ] **Step 3: Implementar el adapter**

`internal/collector/eventlog/eventlog.go`:
```go
package eventlog

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/evtx"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// Collector recolecta y correlaciona Event Logs (.evtx).
type Collector struct {
	SecurityPath  string
	SystemPath    string
	TaskSchedPath string
	SystemHive    string
	SoftwareHive  string
}

func New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector {
	return &Collector{
		SecurityPath:  securityPath,
		SystemPath:    systemPath,
		TaskSchedPath: taskSchedPath,
		SystemHive:    systemHive,
		SoftwareHive:  softwareHive,
	}
}

func (c *Collector) Name() string  { return "eventlog" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	arts := make([]collector.Artifact, 0)

	// Parsear los tres logs; un log ilegible no aborta los demás.
	secLog := c.openLog(c.SecurityPath, "Security", &arts)
	sysLog := c.openLog(c.SystemPath, "System", &arts)
	taskLog := c.openLog(c.TaskSchedPath, "TaskScheduler", &arts)

	logsCleared := false

	for _, log := range []*evtx.Log{secLog, sysLog, taskLog} {
		if log == nil {
			continue
		}
		for _, ts := range log.Tamper {
			arts = appendJSON(arts, "eventlog.tamper_signal", ts.Kind, ts)
		}
		for _, r := range log.Records {
			switch r.EventID {
			case 4624, 4634, 6005, 6006, 6008:
				arts = appendJSON(arts, "eventlog.session_timeline", r.Channel, timelineEntry(r))
			case 1102, 104:
				logsCleared = true
				arts = appendJSON(arts, "eventlog.log_cleared", r.Channel, clearEntry(r))
			}
		}
	}

	installs := collectInstalls(sysLog)
	taskEvents := collectTaskEvents(taskLog)
	curServices := c.currentNonStandardServices()
	curTasks := c.currentNonStandardTasks()

	for _, d := range CrossCheck(installs, curServices, taskEvents, curTasks, logsCleared) {
		arts = appendJSON(arts, "eventlog.desync", d.Subject, d)
	}
	return arts, nil
}

// openLog abre un .evtx; si falla, emite un artifact de error y devuelve nil.
func (c *Collector) openLog(path, channel string, arts *[]collector.Artifact) *evtx.Log {
	if path == "" {
		return nil
	}
	log, err := evtx.Open(path, channel)
	if err != nil {
		*arts = appendJSON(*arts, "eventlog.tamper_signal", channel,
			evtx.TamperSignal{Kind: "log_unreadable", Detail: err.Error()})
		return nil
	}
	return log
}

type timeline struct {
	Time    time.Time `json:"time"`
	EventID uint16    `json:"event_id"`
	User    string    `json:"user,omitempty"`
	Logon   string    `json:"logon_type,omitempty"`
}

func timelineEntry(r evtx.Record) timeline {
	return timeline{Time: r.Timestamp, EventID: r.EventID, User: r.Fields["TargetUserName"], Logon: r.Fields["LogonType"]}
}

type clear struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	By      string    `json:"cleared_by,omitempty"`
}

func clearEntry(r evtx.Record) clear {
	return clear{Time: r.Timestamp, Channel: r.Fields["Channel"], By: r.Fields["SubjectUserName"]}
}

func collectInstalls(log *evtx.Log) []InstallEvent {
	if log == nil {
		return nil
	}
	var out []InstallEvent
	for _, r := range log.Records {
		if r.EventID == 7045 {
			out = append(out, InstallEvent{ServiceName: r.Fields["ServiceName"], ImagePath: r.Fields["ImagePath"]})
		}
	}
	return out
}

func collectTaskEvents(log *evtx.Log) []TaskEvent {
	if log == nil {
		return nil
	}
	var out []TaskEvent
	for _, r := range log.Records {
		var action string
		switch r.EventID {
		case 106:
			action = "register"
		case 140:
			action = "update"
		case 141:
			action = "delete"
		default:
			continue
		}
		out = append(out, TaskEvent{Action: action, TaskName: r.Fields["TaskName"]})
	}
	return out
}

// currentNonStandardServices lee el hive SYSTEM y filtra a drivers no
// Microsoft. Si el hive no está disponible devuelve nil (la correlación de
// servicios se omite, pero el resto del colector sigue).
func (c *Collector) currentNonStandardServices() []winservices.DriverService {
	if c.SystemHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SystemHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		if root, err = h.OpenKey(`ControlSet002\Services`); err != nil {
			return nil
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil
	}
	var out []winservices.DriverService
	for _, s := range all {
		if winservices.IsNonMicrosoftDriver(s) {
			out = append(out, s)
		}
	}
	return out
}

// currentNonStandardTasks lee TaskCache\Tree del hive SOFTWARE y filtra las
// tareas fuera de la carpeta Microsoft\ (las del sistema generan ruido).
func (c *Collector) currentNonStandardTasks() []winscheduler.CachedTask {
	if c.SoftwareHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SoftwareHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	tree, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`)
	if err != nil {
		return nil
	}
	all, err := winscheduler.WalkTaskCacheTree(tree)
	if err != nil {
		return nil
	}
	var out []winscheduler.CachedTask
	for _, t := range all {
		if !strings.HasPrefix(t.RelPath, `Microsoft\`) {
			out = append(out, t)
		}
	}
	return out
}

func appendJSON(arts []collector.Artifact, typ, source string, v any) []collector.Artifact {
	b, _ := json.Marshal(v)
	return append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: time.Now()})
}
```

- [ ] **Step 4: Correr los tests — deben pasar**

Run: `go test ./internal/collector/eventlog/`
Expected: PASS.

- [ ] **Step 5: Verificar build completo y vet**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: todo PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/collector/eventlog/eventlog.go internal/collector/eventlog/eventlog_test.go
git commit -m "feat: colector de Event Logs con timeline, borrado de logs y correlacion

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Wiring en el runtime live

**Files:**
- Modify: `internal/agent/live_windows.go`

**Interfaces:**
- Consumes: `eventlog.New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector`, `vss.PathIn`.
- Produces: el colector `eventlog` registrado en el slice de colectores de `RunLive`.

- [ ] **Step 1: Agregar el import**

En `internal/agent/live_windows.go`, en el bloque de imports, agregar:
```go
	eventlogcol "github.com/telagem/agent-windows/internal/collector/eventlog"
```

- [ ] **Step 2: Derivar los paths de los tres logs**

En `RunLive`, dentro del bloque `if snap, err := vss.Create(...)`, después de las líneas que arman `softwareHive`, agregar la derivación desde VSS; y declarar valores por defecto (fallback en vivo) antes del `if`, junto a los hives:
```go
	securityLog := `C:\Windows\System32\winevt\Logs\Security.evtx`
	systemLog := `C:\Windows\System32\winevt\Logs\System.evtx`
	taskSchedLog := `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`
```
y dentro del `if snap...`:
```go
		securityLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Security.evtx`)
		systemLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\System.evtx`)
		taskSchedLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`)
```

- [ ] **Step 3: Registrar el colector**

En el slice `collectors := []collector.Collector{...}`, después de `schedulercol.New(...)` agregar:
```go
		eventlogcol.New(securityLog, systemLog, taskSchedLog, systemHive, softwareHive),
```

- [ ] **Step 4: Verificar compilación cruzada a Windows**

Run: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`
Expected: compila sin errores.

- [ ] **Step 5: Correr toda la suite**

Run: `go test ./...`
Expected: todo PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/live_windows.go
git commit -m "feat: registrar colector de Event Logs en el entrypoint live

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Notas de cierre

- Tras Task 7, actualizar el estado del spec `2026-07-30-agente-forense-windows-fase-3d-event-logs-design.md` a "Implementado" si se desea, y considerar merge/push a `master` (autorizado) como en fases previas.
- El roadmap KellerSS restante (3E firmas/strings, 3F PCA/crash dumps/temp, 3G hosts/Disco) queda fuera de este plan; cada uno con su propio spec.
