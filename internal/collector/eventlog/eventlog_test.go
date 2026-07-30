package eventlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func writeEvtx(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestCollectEmitsTimelineAndClear(t *testing.T) {
	ts := time.Now().UTC()
	sec := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{evtxtest.StringSub("mirko"), evtxtest.U32Sub(2)}).
		AddRecord(2, ts.Add(time.Minute), 1102, []evtxtest.Sub{evtxtest.StringSub("attacker")}).
		Build()
	secPath := writeEvtx(t, "Security.evtx", sec)

	c := New(secPath, "", "", "", "")
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var timeline, cleared int
	for _, a := range arts {
		switch a.Type {
		case "eventlog.session_timeline":
			timeline++
		case "eventlog.log_cleared":
			cleared++
		}
	}
	if timeline == 0 {
		t.Fatal("esperaba al menos un artifact session_timeline")
	}
	if cleared != 1 {
		t.Fatalf("esperaba 1 log_cleared, obtuve %d", cleared)
	}
}
