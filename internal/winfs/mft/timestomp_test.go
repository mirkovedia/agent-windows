package mft

import (
	"testing"
	"time"
)

func TestDetectNormalNotStomped(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 500, time.UTC)
	si := Timestamps{Created: base, Modified: base.Add(time.Hour), MFTChanged: base, Accessed: base}
	fn := Timestamps{Created: base, Modified: base, MFTChanged: base, Accessed: base}
	if v := DetectTimestomp(si, fn); v.Stomped {
		t.Errorf("archivo normal no debería marcarse: %+v", v)
	}
}

func TestDetectBackdatedCreated(t *testing.T) {
	fnCreated := time.Date(2026, 1, 1, 12, 0, 0, 300, time.UTC)
	si := Timestamps{Created: fnCreated.Add(-48 * time.Hour), Modified: fnCreated}
	fn := Timestamps{Created: fnCreated}
	v := DetectTimestomp(si, fn)
	if !v.Stomped {
		t.Fatal("backdating (SI.Created < FN.Created) debería marcarse")
	}
	if len(v.Reasons) == 0 {
		t.Error("esperaba al menos una razón")
	}
}

func TestDetectModifiedBeforeName(t *testing.T) {
	fnCreated := time.Date(2026, 1, 1, 12, 0, 0, 300, time.UTC)
	si := Timestamps{Created: fnCreated, Modified: fnCreated.Add(-10 * time.Hour)}
	fn := Timestamps{Created: fnCreated}
	if !DetectTimestomp(si, fn).Stomped {
		t.Fatal("SI.Modified < FN.Created debería marcarse")
	}
}

func TestDetectSubSecZeroed(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) // sub-segundo exactamente 0
	si := Timestamps{Created: base, Modified: base}
	fn := Timestamps{Created: base, Modified: base}
	if !DetectTimestomp(si, fn).SubSecZeroed {
		t.Error("esperaba SubSecZeroed con sub-segundos en cero")
	}
}

func TestDetectZeroTimestampsNotStomped(t *testing.T) {
	if DetectTimestomp(Timestamps{}, Timestamps{}).Stomped {
		t.Error("timestamps cero no deberían gatillar detección")
	}
}
