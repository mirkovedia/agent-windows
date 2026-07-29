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
