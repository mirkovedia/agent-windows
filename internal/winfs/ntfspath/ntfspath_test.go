package ntfspath

import "testing"

// testRootRef simula el FileRef de la raíz del volumen (nº de entrada MFT 5).
const testRootRef = 0x0005000000000005

func TestResolvePathFull(t *testing.T) {
	pm := map[uint64]ParentEntry{
		100: {Name: "Users", ParentRef: testRootRef},
		200: {Name: "Downloads", ParentRef: 100},
	}
	got := ResolvePath(pm, 200, "cheat.exe")
	want := `\Users\Downloads\cheat.exe`
	if got != want {
		t.Fatalf("ResolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathMissingParent(t *testing.T) {
	got := ResolvePath(map[uint64]ParentEntry{}, 999, "evil.exe")
	want := `\` + unresolvedPrefix + `\evil.exe`
	if got != want {
		t.Fatalf("ResolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathAtRoot(t *testing.T) {
	got := ResolvePath(map[uint64]ParentEntry{}, testRootRef, "pagefile.sys")
	if got != `\pagefile.sys` {
		t.Fatalf("ResolvePath = %q, want %q", got, `\pagefile.sys`)
	}
}
