package wintime

import (
	"testing"
	"time"
)

func TestFiletimeToTimeKnownValue(t *testing.T) {
	// 0x01D9553EC1174000 = 2023-03-13T00:00:00Z (FILETIME, 100ns desde 1601).
	got := FiletimeToTime(0x01D9553EC1174000)
	want := time.Date(2023, 3, 13, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("FiletimeToTime = %s, want %s", got, want)
	}
}

func TestFiletimeToTimeZeroIsZeroTime(t *testing.T) {
	if got := FiletimeToTime(0); !got.IsZero() {
		t.Fatalf("FiletimeToTime(0) = %s, want cero", got)
	}
}
