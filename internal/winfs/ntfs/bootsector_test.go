// internal/winfs/ntfs/bootsector_test.go
package ntfs

import (
	"encoding/binary"
	"errors"
	"testing"
)

// buildBootSector arma un boot sector NTFS sintético de 512 bytes.
// clustersPerRec sigue la convención NTFS: negativo → 2^(-valor) bytes por registro.
func buildBootSector(bps uint16, spc uint8, mftLCN uint64, clustersPerRec int8) []byte {
	b := make([]byte, 512)
	copy(b[0x03:0x0B], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(b[0x0B:0x0D], bps)
	b[0x0D] = spc
	binary.LittleEndian.PutUint64(b[0x30:0x38], mftLCN)
	b[0x40] = byte(clustersPerRec)
	return b
}

func TestParseBootSectorValid(t *testing.T) {
	b := buildBootSector(512, 8, 786432, -10) // registro = 2^10 = 1024 bytes
	bs, err := ParseBootSector(b)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.BytesPerSector != 512 || bs.SectorsPerCluster != 8 {
		t.Errorf("geometría = %d/%d, want 512/8", bs.BytesPerSector, bs.SectorsPerCluster)
	}
	if bs.ClusterSize != 4096 {
		t.Errorf("ClusterSize = %d, want 4096", bs.ClusterSize)
	}
	if bs.MFTCluster != 786432 {
		t.Errorf("MFTCluster = %d, want 786432", bs.MFTCluster)
	}
	if bs.BytesPerRecord != 1024 {
		t.Errorf("BytesPerRecord = %d, want 1024", bs.BytesPerRecord)
	}
}

func TestParseBootSectorNotNTFS(t *testing.T) {
	b := buildBootSector(512, 8, 100, -10)
	copy(b[0x03:0x0B], []byte("XXXXXXXX"))
	if _, err := ParseBootSector(b); !errors.Is(err, ErrNotNTFS) {
		t.Fatalf("esperaba ErrNotNTFS, obtuve %v", err)
	}
}

func TestParseBootSectorPositiveClustersPerRecord(t *testing.T) {
	// clustersPerRec = 1 → registro = 1 clúster = 512*2 = 1024 bytes.
	b := buildBootSector(512, 2, 100, 1)
	bs, err := ParseBootSector(b)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.BytesPerRecord != 1024 {
		t.Errorf("BytesPerRecord = %d, want 1024", bs.BytesPerRecord)
	}
}

func TestParseBootSectorBadGeometry(t *testing.T) {
	b := buildBootSector(999, 8, 100, -10) // bytes por sector inválido
	if _, err := ParseBootSector(b); err == nil {
		t.Fatal("esperaba error por geometría inválida")
	}
}
