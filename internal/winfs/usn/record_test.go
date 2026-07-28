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

// buildV3 construye un USN_RECORD_V3 sintético para testeo (76 bytes de header fijo).
func buildV3(fileRef, parentRef uint64, usn int64, ft uint64, reason uint32, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], c)
	}
	const fixed = 0x4C // 76 bytes de header fijo V3
	recLen := fixed + len(nameBytes)
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(buf[4:6], 3) // MajorVersion
	binary.LittleEndian.PutUint64(buf[0x08:0x10], fileRef)      // FileRef low64
	binary.LittleEndian.PutUint64(buf[0x10:0x18], 0)            // FileRef high64
	binary.LittleEndian.PutUint64(buf[0x18:0x20], parentRef)    // ParentRef low64
	binary.LittleEndian.PutUint64(buf[0x20:0x28], 0)            // ParentRef high64
	binary.LittleEndian.PutUint64(buf[0x28:0x30], uint64(usn))
	binary.LittleEndian.PutUint64(buf[0x30:0x38], ft)
	binary.LittleEndian.PutUint32(buf[0x38:0x3C], reason)
	binary.LittleEndian.PutUint16(buf[0x48:0x4A], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(buf[0x4A:0x4C], fixed)
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

func TestParseRecordV3(t *testing.T) {
	buf := buildV3(0x5566, 0x7788, 99, 0x01D9553EC1174000, ReasonDataOverwrite, "malware.exe")
	rec, n, err := parseRecord(buf)
	if err != nil {
		t.Fatalf("parseRecord error: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("RecordLength = %d, want %d", n, len(buf))
	}
	if rec.FileName != "malware.exe" {
		t.Fatalf("FileName = %q", rec.FileName)
	}
	if rec.FileRef != 0x5566 || rec.ParentRef != 0x7788 {
		t.Fatalf("refs = %x/%x", rec.FileRef, rec.ParentRef)
	}
	if rec.Reason&ReasonDataOverwrite == 0 {
		t.Fatalf("Reason = %x, sin ReasonDataOverwrite", rec.Reason)
	}
	if rec.Timestamp.IsZero() {
		t.Fatal("Timestamp no debería ser cero")
	}
	if rec.USN != 99 {
		t.Fatalf("USN = %d, want 99", rec.USN)
	}
}
