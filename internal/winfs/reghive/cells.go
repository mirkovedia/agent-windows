package reghive

import (
	"encoding/binary"
	"fmt"
)

// subkeyByName busca una subclave por nombre (case-insensitive).
func (k *Key) subkeyByName(name string) (*Key, error) {
	subs, err := k.Subkeys()
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		if equalFold(s.Name(), name) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("subclave %q no encontrada", name)
}

// Subkeys devuelve las subclaves de la clave, leyendo la subkey-list.
func (k *Key) Subkeys() ([]*Key, error) {
	if len(k.nk) < 36 {
		return nil, fmt.Errorf("celda nk truncada")
	}
	subkeyCount := binary.LittleEndian.Uint32(k.nk[20:24])
	if subkeyCount == 0 {
		return nil, nil
	}
	listOffset := binary.LittleEndian.Uint32(k.nk[28:32])
	list := k.hive.cellBody(listOffset)
	if len(list) < 2 {
		return nil, fmt.Errorf("subkey-list inválida")
	}
	offsets, err := parseSubkeyList(k.hive, list)
	if err != nil {
		return nil, err
	}
	keys := make([]*Key, 0, len(offsets))
	for _, off := range offsets {
		if kk := k.hive.readKeyAt(off); kk != nil {
			keys = append(keys, kk)
		}
	}
	return keys, nil
}

// parseSubkeyList resuelve los tipos de lista lf/lh/li/ri a offsets de nk.
func parseSubkeyList(h *Hive, list []byte) ([]uint32, error) {
	sig := string(list[:2])
	switch sig {
	case "lf", "lh":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		offsets := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			base := 4 + i*8 // cada entrada: offset(4) + hash(4)
			if base+4 > len(list) {
				break
			}
			offsets = append(offsets, binary.LittleEndian.Uint32(list[base:base+4]))
		}
		return offsets, nil
	case "li":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		offsets := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(list) {
				break
			}
			offsets = append(offsets, binary.LittleEndian.Uint32(list[base:base+4]))
		}
		return offsets, nil
	case "ri":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		var all []uint32
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(list) {
				break
			}
			subListOff := binary.LittleEndian.Uint32(list[base : base+4])
			subList := h.cellBody(subListOff)
			if len(subList) < 2 {
				continue
			}
			offs, err := parseSubkeyList(h, subList)
			if err != nil {
				return nil, err
			}
			all = append(all, offs...)
		}
		return all, nil
	default:
		return nil, fmt.Errorf("tipo de subkey-list desconocido: %q", sig)
	}
}

// Value devuelve los datos crudos y el tipo de un valor por nombre.
func (k *Key) Value(name string) ([]byte, uint32, error) {
	values, types, err := k.valuesAndTypes()
	if err != nil {
		return nil, 0, err
	}
	for n, data := range values {
		if equalFold(n, name) {
			return data, types[n], nil
		}
	}
	return nil, 0, fmt.Errorf("valor %q no encontrado", name)
}

// Values devuelve todos los valores de la clave (nombre → datos crudos).
func (k *Key) Values() (map[string][]byte, error) {
	v, _, err := k.valuesAndTypes()
	return v, err
}

func (k *Key) valuesAndTypes() (map[string][]byte, map[string]uint32, error) {
	if len(k.nk) < 44 {
		return nil, nil, fmt.Errorf("celda nk truncada")
	}
	valueCount := binary.LittleEndian.Uint32(k.nk[36:40])
	values := make(map[string][]byte, valueCount)
	types := make(map[string]uint32, valueCount)
	if valueCount == 0 {
		return values, types, nil
	}
	valueListOffset := binary.LittleEndian.Uint32(k.nk[40:44])
	valueList := k.hive.cellBody(valueListOffset)
	for i := 0; i < int(valueCount); i++ {
		base := i * 4
		if base+4 > len(valueList) {
			break
		}
		vkOffset := binary.LittleEndian.Uint32(valueList[base : base+4])
		name, data, typ := k.hive.readValue(vkOffset)
		values[name] = data
		types[name] = typ
	}
	return values, types, nil
}

// readValue lee una celda vk: nombre, datos y tipo.
func (h *Hive) readValue(offset uint32) (string, []byte, uint32) {
	vk := h.cellBody(offset)
	if len(vk) < 20 || string(vk[:2]) != "vk" {
		return "", nil, 0
	}
	nameLen := int(binary.LittleEndian.Uint16(vk[2:4]))
	dataLen := binary.LittleEndian.Uint32(vk[4:8])
	dataOffset := binary.LittleEndian.Uint32(vk[8:12])
	dataType := binary.LittleEndian.Uint32(vk[12:16])

	var name string
	if nameLen > 0 && 20+nameLen <= len(vk) {
		name = string(vk[20 : 20+nameLen])
	}

	const inlineFlag = 0x80000000
	var data []byte
	if dataLen&inlineFlag != 0 {
		// datos residentes: hasta 4 bytes en el propio campo dataOffset
		n := dataLen &^ inlineFlag
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, dataOffset)
		if n > 4 {
			n = 4
		}
		data = raw[:n]
	} else {
		data = h.cellBody(dataOffset)
		if uint32(len(data)) > dataLen {
			data = data[:dataLen]
		}
	}
	return name, data, dataType
}

// equalFold compara nombres de clave/valor sin distinguir mayúsculas (ASCII).
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
