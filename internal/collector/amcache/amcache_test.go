package amcache

import "testing"

func TestNormalizeFileIDStripsPrefix(t *testing.T) {
	// FileId en AmCache viene como "0000" + SHA-1 (44 chars total).
	raw := "0000aabbccddeeff00112233445566778899aabb"
	got := normalizeFileID(raw)
	if got != "aabbccddeeff00112233445566778899aabb" {
		t.Fatalf("normalizeFileID = %q", got)
	}
}

func TestNormalizeFileIDShortReturnsAsIs(t *testing.T) {
	if got := normalizeFileID("abc"); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
