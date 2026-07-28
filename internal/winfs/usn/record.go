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
// llamador pueda saltear el record y continuar. Si RecordLength es inválido,
// devuelve n=0 (no se puede avanzar con seguridad).
func parseRecord(buf []byte) (Record, int, error) {
	if len(buf) < 4 {
		return Record{}, 0, fmt.Errorf("buffer USN truncado: %d bytes", len(buf))
	}
	recLen := int(binary.LittleEndian.Uint32(buf[0:4]))
	if recLen < 8 || recLen > len(buf) {
		// No se puede avanzar: el campo RecordLength es inválido o no es confiable;
		// devolvemos n=0 para que el llamador se detenga, ya que no es seguro saltear.
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
