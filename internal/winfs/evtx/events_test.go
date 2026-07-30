package evtx

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/evtx/evtxtest"
)

func TestFieldsForLogon(t *testing.T) {
	data := evtxtest.NewBuilder().
		AddRecord(1, time.Now().UTC(), 4624, []evtxtest.Sub{
			evtxtest.StringSub("mirko"),
			evtxtest.U32Sub(10),
		}).Build()
	log, _ := parseLog(data, "Security")
	f := log.Records[0].Fields
	if f["TargetUserName"] != "mirko" {
		t.Fatalf("TargetUserName inesperado: %q", f["TargetUserName"])
	}
	if f["LogonType"] != "10" {
		t.Fatalf("LogonType inesperado: %q", f["LogonType"])
	}
}

func TestFieldsForServiceInstall(t *testing.T) {
	data := evtxtest.NewBuilder().
		AddRecord(1, time.Now().UTC(), 7045, []evtxtest.Sub{
			evtxtest.StringSub("EvilDrv"),
			evtxtest.StringSub(`C:\Temp\evil.sys`),
		}).Build()
	log, _ := parseLog(data, "System")
	f := log.Records[0].Fields
	if f["ServiceName"] != "EvilDrv" || f["ImagePath"] != `C:\Temp\evil.sys` {
		t.Fatalf("campos 7045 inesperados: %+v", f)
	}
}
