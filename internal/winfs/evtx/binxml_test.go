package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestDecodeBinXMLReadsSubstitutions(t *testing.T) {
	ts := time.Now().UTC()
	data := evtxtest.NewBuilder().
		AddRecord(1, ts, 4624, []evtxtest.Sub{
			evtxtest.StringSub("mirko"),
			evtxtest.U32Sub(10), // LogonType RDP
		}).
		Build()
	log, _ := parseLog(data, "Security")
	r := log.Records[0]
	if r.EventID != 4624 {
		t.Fatalf("EventID esperado 4624, obtuve %d", r.EventID)
	}
	if r.PartialDecode {
		t.Fatal("no debería ser PartialDecode")
	}
	// subs[0] es el EventID; subs[1..] los campos.
	if len(r.Subs) != 3 {
		t.Fatalf("esperaba 3 subs, obtuve %d", len(r.Subs))
	}
	if r.Subs[1].Type != TypeString {
		t.Fatalf("sub[1] debería ser string, tipo %#x", r.Subs[1].Type)
	}
}

func TestDecodeBinXMLPartialOnGarbage(t *testing.T) {
	_, _, partial := decodeBinXML([]byte{0xFF, 0xFF, 0xFF})
	if !partial {
		t.Fatal("payload basura debería marcar partial")
	}
}
