package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func hasTamper(log *Log, kind string) bool {
	for _, t := range log.Tamper {
		if t.Kind == kind {
			return true
		}
	}
	return false
}

func TestTamperRecordIDGap(t *testing.T) {
	ts := time.Now().UTC()
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, nil).
		AddRecord(5, ts, 4624, nil). // salto 1 -> 5
		Build()
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "record_id_gap") {
		t.Fatal("esperaba señal record_id_gap")
	}
}

func TestTamperDirtyFlag(t *testing.T) {
	data := evtxtest.NewBuilder().WithDirty().AddRecord(1, time.Now().UTC(), 4624, nil).Build()
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "dirty_flag") {
		t.Fatal("esperaba señal dirty_flag")
	}
}

func TestTamperChunkCRCInvalid(t *testing.T) {
	data := evtxtest.NewBuilder().AddRecord(1, time.Now().UTC(), 4624, nil).Build()
	data[4096+512+8]++ // corromper datos del chunk sin recomputar CRC
	log, _ := parseLog(data, "Security")
	if !hasTamper(log, "chunk_crc_invalid") {
		t.Fatal("esperaba señal chunk_crc_invalid")
	}
}
