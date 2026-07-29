// internal/winfs/ntfs/dataruns_test.go
package ntfs

import (
	"encoding/binary"
	"testing"
)

func TestDecodeDataRunsSingle(t *testing.T) {
	// header 0x21 → lenSize=1, offSize=2; length=0x08; offset=0x0140 (320).
	runs := []byte{0x21, 0x08, 0x40, 0x01, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 1 {
		t.Fatalf("len(ex) = %d, want 1", len(ex))
	}
	if ex[0].StartLCN != 320 || ex[0].Length != 8 {
		t.Errorf("extent = %+v, want {320, 8}", ex[0])
	}
}

func TestDecodeDataRunsMultipleContiguous(t *testing.T) {
	// run1: 0x11 len=0x30 off=0x60 → lcn=0x60. run2: 0x11 len=0x10 off=0x05 → lcn=0x65.
	runs := []byte{0x11, 0x30, 0x60, 0x11, 0x10, 0x05, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 2 || ex[0].StartLCN != 0x60 || ex[1].StartLCN != 0x65 {
		t.Fatalf("extents = %+v", ex)
	}
}

func TestDecodeDataRunsNegativeOffset(t *testing.T) {
	// run1: lcn=64. run2: off=0xFF (−1) → lcn=63.
	runs := []byte{0x11, 0x10, 0x40, 0x11, 0x10, 0xFF, 0x00}
	ex, err := DecodeDataRuns(runs)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if ex[1].StartLCN != 63 {
		t.Errorf("segundo LCN = %d, want 63 (delta negativo)", ex[1].StartLCN)
	}
}

func TestDecodeDataRunsTruncated(t *testing.T) {
	runs := []byte{0x21, 0x08, 0x40} // falta un byte del offset
	if _, err := DecodeDataRuns(runs); err == nil {
		t.Fatal("esperaba error por data run truncado")
	}
}

// buildNonResidentData arma un atributo $DATA no-residente con los mapping pairs dados.
func buildNonResidentData(runs []byte) []byte {
	const hdr = 0x40 // header no-residente sin nombre; mapping pairs a 0x40
	total := hdr + len(runs)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], 0x80) // tipo $DATA
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 1                                          // flag no-residente
	binary.LittleEndian.PutUint16(a[0x20:0x22], hdr) // mapping pairs offset
	copy(a[hdr:], runs)
	return a
}

// buildFileRecord arma un registro FILE mínimo (sin scramble de fixup) con los atributos dados.
func buildFileRecord(attrs ...[]byte) []byte {
	buf := make([]byte, 1024)
	copy(buf[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(buf[0x04:0x06], 0x30) // USA offset
	binary.LittleEndian.PutUint16(buf[0x06:0x08], 3)    // USA count
	binary.LittleEndian.PutUint16(buf[0x14:0x16], 0x38) // primer atributo
	off := 0x38
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}
	binary.LittleEndian.PutUint32(buf[off:off+4], 0xFFFFFFFF) // terminador
	return buf
}

func TestNonResidentDataRunsLocatesData(t *testing.T) {
	runs := []byte{0x11, 0x08, 0x40, 0x00} // 1 run: lcn=0x40, len=0x08
	rec := buildFileRecord(buildNonResidentData(runs))
	got, err := nonResidentDataRuns(rec)
	if err != nil {
		t.Fatalf("nonResidentDataRuns: %v", err)
	}
	ex, err := DecodeDataRuns(got)
	if err != nil {
		t.Fatalf("DecodeDataRuns: %v", err)
	}
	if len(ex) != 1 || ex[0].StartLCN != 0x40 || ex[0].Length != 8 {
		t.Fatalf("extents = %+v", ex)
	}
}

func TestNonResidentDataRunsMissing(t *testing.T) {
	rec := buildFileRecord() // sin atributos
	if _, err := nonResidentDataRuns(rec); err == nil {
		t.Fatal("esperaba error si no hay $DATA no-residente")
	}
}
