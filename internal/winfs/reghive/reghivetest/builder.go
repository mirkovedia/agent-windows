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
