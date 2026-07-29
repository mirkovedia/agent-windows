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
	FileName  string
	ParentRef uint64 // referencia MFT del directorio padre (de los 8 primeros bytes del $FN)

	fnNamespace byte // namespace del $FN ya tomado (para preferir el nombre largo)
}

const (
	fileSignature    = 0x454C4946 // "FILE" en little-endian
	attrStandardInfo = 0x10
	attrFileName     = 0x30
	attrTerminator   = 0xFFFFFFFF
	sectorSize       = 512
	dosNamespace     = 2 // namespace 8.3
)

// ErrBadSignature indica que el buffer no empieza con la firma "FILE".
var ErrBadSignature = errors.New("registro MFT sin firma FILE")

// ParseRecord parsea un registro FILE del MFT: valida firma, aplica el update
// sequence array fixup y extrae SI (0x10) y FN (0x30) de los atributos residentes.
func ParseRecord(buf []byte) (Record, error) {
	if len(buf) < 0x30 {
		return Record{}, errors.New("registro MFT truncado")
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != fileSignature {
		return Record{}, ErrBadSignature
	}
	fixed, err := ApplyFixup(buf)
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

// ApplyFixup restaura los últimos 2 bytes de cada sector, que NTFS reemplaza por
// el update sequence number al escribir. Devuelve una copia corregida del buffer.
func ApplyFixup(buf []byte) ([]byte, error) {
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
	r.ParentRef = binary.LittleEndian.Uint64(c[0x00:0x08])
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
