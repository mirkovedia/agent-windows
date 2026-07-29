// internal/winfs/ntfs/bootsector.go
package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotNTFS indica que el sector 0 no tiene la firma OEM "NTFS".
var ErrNotNTFS = errors.New("volumen no es NTFS (falta firma OEM)")

// BootSector describe la geometría NTFS necesaria para ubicar y leer el $MFT.
type BootSector struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	MFTCluster        uint64 // LCN del primer clúster del $MFT
	BytesPerRecord    int    // tamaño de un registro FILE (típico 1024)
	ClusterSize       int    // BytesPerSector * SectorsPerCluster
}

// ParseBootSector valida la firma NTFS y extrae la geometría del sector 0 (>=512 bytes).
func ParseBootSector(sector []byte) (BootSector, error) {
	if len(sector) < 0x50 {
		return BootSector{}, errors.New("boot sector truncado")
	}
	if string(sector[0x03:0x0B]) != "NTFS    " {
		return BootSector{}, ErrNotNTFS
	}
	bps := binary.LittleEndian.Uint16(sector[0x0B:0x0D])
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return BootSector{}, fmt.Errorf("bytes por sector inválido: %d", bps)
	}
	spc := sector[0x0D]
	if spc == 0 {
		return BootSector{}, errors.New("sectores por clúster es cero")
	}
	clusterSize := int(bps) * int(spc)

	mftCluster := binary.LittleEndian.Uint64(sector[0x30:0x38])

	// ClustersPerFileRecordSegment: si es positivo, nº de clústers por registro;
	// si es negativo, el tamaño del registro es 2^(-valor) bytes.
	raw := int8(sector[0x40])
	var bytesPerRecord int
	if raw >= 0 {
		bytesPerRecord = int(raw) * clusterSize
	} else {
		bytesPerRecord = 1 << uint(-raw)
	}
	if bytesPerRecord < 512 {
		return BootSector{}, fmt.Errorf("tamaño de registro inválido: %d", bytesPerRecord)
	}

	return BootSector{
		BytesPerSector:    bps,
		SectorsPerCluster: spc,
		MFTCluster:        mftCluster,
		BytesPerRecord:    bytesPerRecord,
		ClusterSize:       clusterSize,
	}, nil
}
