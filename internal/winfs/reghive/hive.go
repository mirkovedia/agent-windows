package reghive

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	regfSignature = "regf"
	baseBlockSize = 0x1000 // el header regf ocupa 4 KiB; las celdas empiezan después
)

// Hive es un hive del registro (formato regf) parseado desde memoria.
type Hive struct {
	data           []byte // solo la región de celdas (después del base block)
	rootCellOffset uint32
}

// Open valida el header regf y localiza la celda raíz.
func Open(data []byte) (*Hive, error) {
	if len(data) < baseBlockSize {
		return nil, fmt.Errorf("hive muy corto: %d bytes", len(data))
	}
	if string(data[:4]) != regfSignature {
		return nil, fmt.Errorf("firma regf inválida: %q", data[:4])
	}
	rootOffset := binary.LittleEndian.Uint32(data[36:40])
	return &Hive{
		data:           data[baseBlockSize:],
		rootCellOffset: rootOffset,
	}, nil
}

// Key es una clave del registro (celda nk).
type Key struct {
	hive *Hive
	nk   []byte // cuerpo de la celda nk
}

// OpenKey navega desde la raíz por un path separado por "\".
func (h *Hive) OpenKey(path string) (*Key, error) {
	current := h.readKeyAt(h.rootCellOffset)
	if current == nil {
		return nil, fmt.Errorf("celda raíz inválida en offset 0x%x", h.rootCellOffset)
	}
	if path == "" {
		return current, nil
	}
	for _, part := range strings.Split(path, `\`) {
		next, err := current.subkeyByName(part)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// readKeyAt lee una celda nk en el offset dado (relativo a la región de celdas).
func (h *Hive) readKeyAt(offset uint32) *Key {
	body := h.cellBody(offset)
	if len(body) < 2 || string(body[:2]) != "nk" {
		return nil
	}
	return &Key{hive: h, nk: body}
}

// cellBody devuelve el contenido de una celda (saltando el prefijo de tamaño
// de 4 bytes). offset es relativo al inicio de la región de celdas.
func (h *Hive) cellBody(offset uint32) []byte {
	if int(offset)+4 > len(h.data) {
		return nil
	}
	size := int32(binary.LittleEndian.Uint32(h.data[offset : offset+4]))
	if size < 0 {
		size = -size // celda asignada: tamaño negativo
	}
	start := int(offset) + 4
	end := int(offset) + int(size)
	if start > len(h.data) || end > len(h.data) || start >= end {
		return nil
	}
	return h.data[start:end]
}

// Name devuelve el nombre de la clave.
func (k *Key) Name() string {
	if len(k.nk) < 76 {
		return ""
	}
	nameLen := int(binary.LittleEndian.Uint16(k.nk[72:74]))
	if 76+nameLen > len(k.nk) {
		return ""
	}
	return string(k.nk[76 : 76+nameLen])
}
