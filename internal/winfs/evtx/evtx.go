// Package evtx parsea archivos Windows Event Log (.evtx) de forma pura, sin
// depender del servicio EventLog. Implementa el framing real (header ELF,
// chunks, records, CRC32) y un decodificador BinXML pragmático scopeado a los
// EventIDs forenses; ante estructuras no soportadas degrada a PartialDecode.
package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/wintime"
)

// Tipos de value BinXML soportados.
const (
	TypeString   = 0x01
	TypeUInt16   = 0x06
	TypeUInt32   = 0x08
	TypeFileTime = 0x11
)

// SubValue es un valor de la substitution array de un record.
type SubValue struct {
	Type uint8
	Raw  []byte
}

// Record es un evento parseado.
type Record struct {
	ID            uint64
	Timestamp     time.Time
	EventID       uint16
	Channel       string
	PartialDecode bool
	Subs          []SubValue
	Fields        map[string]string
}

// TamperSignal es una anomalía estructural del archivo.
type TamperSignal struct {
	Kind     string
	Detail   string
	RecordID uint64
}

// Log es el resultado de parsear un .evtx completo.
type Log struct {
	Records []Record
	Tamper  []TamperSignal
	Dirty   bool
	Full    bool
}

const chunkSize = 65536

// Open lee y parsea un archivo .evtx, etiquetando cada record con channel.
func Open(path, channel string) (*Log, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseLog(data, channel)
}

func parseLog(data []byte, channel string) (*Log, error) {
	if len(data) < 4096 || string(data[0:8]) != "ElfFile\x00" {
		return nil, errors.New("evtx: header ElfFile inválido")
	}
	log := &Log{}
	flags := binary.LittleEndian.Uint32(data[120:124])
	log.Dirty = flags&0x1 != 0
	log.Full = flags&0x2 != 0

	checkFileFlags(log)
	for off := 4096; off+chunkSize <= len(data); off += chunkSize {
		chunk := data[off : off+chunkSize]
		if string(chunk[0:8]) != "ElfChnk\x00" {
			break
		}
		checkChunkCRC(chunk, log)
		parseChunkRecords(chunk, channel, log)
	}
	checkRecordGaps(log.Records, log)
	return log, nil
}

// parseChunkRecords extrae los records de un chunk (sin validar CRC ni
// decodificar BinXML todavía: eso lo agregan Task 2 y Task 3).
func parseChunkRecords(chunk []byte, channel string, log *Log) {
	freeSpace := binary.LittleEndian.Uint32(chunk[48:52])
	for off := uint32(512); off+24 <= freeSpace && off+24 <= uint32(len(chunk)); {
		if binary.LittleEndian.Uint32(chunk[off:off+4]) != 0x00002a2a {
			break
		}
		size := binary.LittleEndian.Uint32(chunk[off+4 : off+8])
		if size < 32 || off+size > uint32(len(chunk)) {
			break
		}
		r := Record{
			ID:        binary.LittleEndian.Uint64(chunk[off+8 : off+16]),
			Timestamp: wintime.FiletimeToTime(binary.LittleEndian.Uint64(chunk[off+16 : off+24])),
			Channel:   channel,
		}
		log.Records = append(log.Records, r)
		off += size
	}
}
