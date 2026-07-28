package usn

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildV2 construye un USN_RECORD_V2 sintético para testeo.
func buildV2(fileRef, parentRef uint64, usn int64, ft uint64, reason uint32, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], c)
	}
	const fixed = 0x3C // 60 bytes de header fijo V2
	recLen := fixed + len(nameBytes)
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(buf[4:6], 2) // MajorVersion
	binary.LittleEndian.PutUint64(buf[0x08:0x10], fileRef)
	binary.LittleEndian.PutUint64(buf[0x10:0x18], parentRef)
	binary.LittleEndian.PutUint64(buf[0x18:0x20], uint64(usn))
	binary.LittleEndian.PutUint64(buf[0x20:0x28], ft)
	binary.LittleEndian.PutUint32(buf[0x28:0x2C], reason)
	binary.LittleEndian.PutUint16(buf[0x38:0x3A], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(buf[0x3A:0x3C], fixed)
	copy(buf[fixed:], nameBytes)
	return buf
}

func TestParseRecordV2(t *testing.T) {
	buf := buildV2(0x1122, 0x3344, 42, 0x01D9553EC1174000, ReasonFileDelete, "cheat.exe")
	rec, n, err := parseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord error: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("RecordLength = %d, want %d", n, len(buf))
	}
	if rec.FileName != "cheat.exe" {
		t.Fatalf("FileName = %q", rec.FileName)
	}
	if rec.FileRef != 0x1122 || rec.ParentRef != 0x3344 {
		t.Fatalf("refs = %x/%x", rec.FileRef, rec.ParentRef)
	}
	if rec.Reason&ReasonFileDelete == 0 {
		t.Fatalf("Reason = %x, sin ReasonFileDelete", rec.Reason)
	}
	if rec.Timestamp.IsZero() {
		t.Fatal("Timestamp no debería ser cero")
	}
}

func TestParseRecordTruncated(t *testing.T) {
	if _, _, err := parseRecord([]byte{0x01, 0x02}); err == nil {
		t.Fatal("esperaba error con buffer truncado")
	}
}

func TestParseRecordUnknownVersionReturnsLength(t *testing.T) {
	buf := buildV2(1, 2, 3, 0, ReasonFileCreate, "x.exe")
	binary.LittleEndian.PutUint16(buf[4:6], 9) // versión inexistente
	_, n, err := parseRecord(buf)
	if err == nil {
		t.Fatal("esperaba error con versión desconocida")
	}
	if n != len(buf) {
		t.Fatalf("RecordLength = %d, want %d (para poder saltear)", n, len(buf))
	}
}
