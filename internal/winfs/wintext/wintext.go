// internal/winfs/wintext/wintext.go
package wintext

import "encoding/binary"

// DecodeUTF16 decodifica una cadena UTF-16LE terminada en \x00\x00, o hasta
// agotar el buffer si no hay terminador. Usado para valores de registro
// REG_SZ/REG_EXPAND_SZ y para contenido XML tras remover el BOM.
func DecodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}
