package evtx

import "encoding/binary"

const (
	tokenFragmentHeader   = 0x0F
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
