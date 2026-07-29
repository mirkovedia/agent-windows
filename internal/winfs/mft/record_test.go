package mft

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildAttr arma un atributo residente (header 0x18 + contenido, alineado a 8).
func buildAttr(attrType uint32, content []byte) []byte {
	const hdr = 0x18
	total := hdr + len(content)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 0 // residente
	binary.LittleEndian.PutUint32(a[0x10:0x14], uint32(len(content)))
	binary.LittleEndian.PutUint16(a[0x14:0x16], hdr)
	copy(a[hdr:], content)
	return a
}

// siContent arma el contenido de un $STANDARD_INFORMATION (0x48 bytes).
func siContent(created, modified, mftChanged, accessed uint64) []byte {
	c := make([]byte, 0x48)
	binary.LittleEndian.PutUint64(c[0x00:], created)
	binary.LittleEndian.PutUint64(c[0x08:], modified)
	binary.LittleEndian.PutUint64(c[0x10:], mftChanged)
	binary.LittleEndian.PutUint64(c[0x18:], accessed)
	return c
}

// fnContent arma el contenido de un $FILE_NAME con nombre UTF-16.
func fnContent(created, modified, mftChanged, accessed uint64, namespace byte, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	c := make([]byte, 0x42+len(u16)*2)
	binary.LittleEndian.PutUint64(c[0x08:], created)
	binary.LittleEndian.PutUint64(c[0x10:], modified)
	binary.LittleEndian.PutUint64(c[0x18:], mftChanged)
	binary.LittleEndian.PutUint64(c[0x20:], accessed)
	c[0x40] = byte(len(u16))
	c[0x41] = namespace
	for i, ch := range u16 {
		binary.LittleEndian.PutUint16(c[0x42+i*2:], ch)
	}
	return c
}

// buildRecord arma un registro FILE de 1024 bytes con el fixup "en disco"
// aplicado (bytes de fin de sector reemplazados por el número de secuencia).
func buildRecord(flags uint16, attrs ...[]byte) []byte {
	const (
		size      = 1024
		usaOff    = 0x30
		usaCount  = 3 // 1 secuencia + 2 sectores
		firstAttr = 0x38
		seq       = 0x0001
	)
	buf := make([]byte, size)
	copy(buf[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(buf[0x04:], usaOff)
	binary.LittleEndian.PutUint16(buf[0x06:], usaCount)
	binary.LittleEndian.PutUint16(buf[0x14:], firstAttr)
	binary.LittleEndian.PutUint16(buf[0x16:], flags)
	off := firstAttr
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}
	binary.LittleEndian.PutUint32(buf[off:], 0xFFFFFFFF) // terminador de atributos
	// Simular el fixup: guardar los bytes reales de fin de sector en la USA y
	// escribir el número de secuencia en su lugar.
	binary.LittleEndian.PutUint16(buf[usaOff:], seq)
	for i := 0; i < usaCount-1; i++ {
		sectorEnd := (i+1)*512 - 2
		orig := binary.LittleEndian.Uint16(buf[sectorEnd : sectorEnd+2])
		binary.LittleEndian.PutUint16(buf[usaOff+2*(i+1):], orig)
		binary.LittleEndian.PutUint16(buf[sectorEnd:], seq)
	}
	return buf
}

const ftKnown = 0x01D9553EC1174000 // 2023-03-13T00:00:00Z

func TestParseRecordExtractsSIandFN(t *testing.T) {
	si := siContent(ftKnown, ftKnown+10, ftKnown, ftKnown)
	fn := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "cheat.exe")
	buf := buildRecord(0x0001, buildAttr(0x10, si), buildAttr(0x30, fn))
	rec, err := ParseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if !rec.InUse {
		t.Error("InUse debería ser true")
	}
	if !rec.HasSI || !rec.HasFN {
		t.Fatalf("faltan SI(%v) o FN(%v)", rec.HasSI, rec.HasFN)
	}
	if rec.FileName != "cheat.exe" {
		t.Errorf("FileName = %q, want cheat.exe", rec.FileName)
	}
	if rec.SI.Created.IsZero() || rec.FN.Created.IsZero() {
		t.Error("timestamps no deberían ser cero")
	}
}

func TestParseRecordBadSignature(t *testing.T) {
	buf := buildRecord(0x0001, buildAttr(0x10, siContent(ftKnown, ftKnown, ftKnown, ftKnown)))
	buf[0] = 'X' // rompe la firma "FILE"
	if _, err := ParseRecord(buf); err == nil {
		t.Fatal("esperaba error con firma inválida")
	}
}

func TestParseRecordPrefersLongName(t *testing.T) {
	long := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "cheatengine.exe")
	dos := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 2, "CHEAT~1.EXE")
	buf := buildRecord(0x0001, buildAttr(0x30, long), buildAttr(0x30, dos))
	rec, err := ParseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if rec.FileName != "cheatengine.exe" {
		t.Errorf("FileName = %q, want cheatengine.exe (no el 8.3)", rec.FileName)
	}
}

func TestParseRecordFixupMismatch(t *testing.T) {
	buf := buildRecord(0x0001, buildAttr(0x10, siContent(ftKnown, ftKnown, ftKnown, ftKnown)))
	buf[0x1FE] ^= 0xFF // corrompe el fin del primer sector
	if _, err := ParseRecord(buf); err == nil {
		t.Fatal("esperaba error por número de secuencia que no coincide")
	}
}
