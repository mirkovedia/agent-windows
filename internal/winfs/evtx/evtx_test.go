package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestParseLogReadsRecords(t *testing.T) {
	ts := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{evtxtest.StringSub("mirko")}).
		AddRecord(2, ts.Add(time.Minute), 4634, []evtxtest.Sub{evtxtest.StringSub("mirko")}).
		Build()

	log, err := parseLog(data, "Security")
	if err != nil {
		t.Fatalf("parseLog: %v", err)
	}
	if len(log.Records) != 2 {
		t.Fatalf("esperaba 2 records, obtuve %d", len(log.Records))
	}
	if log.Records[0].ID != 1 || log.Records[1].ID != 2 {
		t.Fatalf("ids inesperados: %d, %d", log.Records[0].ID, log.Records[1].ID)
	}
	if !log.Records[0].Timestamp.Equal(ts) {
		t.Fatalf("timestamp inesperado: %v", log.Records[0].Timestamp)
	}
	if log.Records[0].Channel != "Security" {
		t.Fatalf("channel inesperado: %q", log.Records[0].Channel)
	}
}
