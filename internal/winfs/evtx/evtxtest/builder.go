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
