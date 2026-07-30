package evtx

import (
	"fmt"
	"hash/crc32"
)

// checkChunkCRC valida el checksum del header del chunk (bytes 0:120 ++
// 128:512) y el de los records (512:freeSpace). Cualquier mismatch es señal
// de manipulación directa del archivo.
func checkChunkCRC(chunk []byte, log *Log) {
	freeSpace := readU32(chunk, 48)
	if freeSpace < 512 || freeSpace > uint32(len(chunk)) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "truncated", Detail: "freeSpaceOffset fuera de rango"})
		return
	}
	h := crc32.NewIEEE()
	h.Write(chunk[0:120])
	h.Write(chunk[128:512])
	if h.Sum32() != readU32(chunk, 124) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "chunk_crc_invalid", Detail: "header checksum"})
	}
	if crc32.ChecksumIEEE(chunk[512:freeSpace]) != readU32(chunk, 52) {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "chunk_crc_invalid", Detail: "records checksum"})
	}
}

// checkRecordGaps detecta saltos en el id monotónico de record: evidencia de
// registros borrados. Debe llamarse una vez con todos los records en orden.
func checkRecordGaps(records []Record, log *Log) {
	for i := 1; i < len(records); i++ {
		if records[i].ID > records[i-1].ID+1 {
			log.Tamper = append(log.Tamper, TamperSignal{
				Kind:     "record_id_gap",
				Detail:   fmt.Sprintf("salto de %d a %d", records[i-1].ID, records[i].ID),
				RecordID: records[i].ID,
			})
		}
	}
}

func checkFileFlags(log *Log) {
	if log.Dirty {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "dirty_flag", Detail: "archivo cerrado sucio"})
	}
	if log.Full {
		log.Tamper = append(log.Tamper, TamperSignal{Kind: "full_flag", Detail: "archivo marcado lleno"})
	}
}

func readU32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}
