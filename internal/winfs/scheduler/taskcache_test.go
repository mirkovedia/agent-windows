// internal/winfs/scheduler/taskcache_test.go
package scheduler

import (
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/reghive/reghivetest"
)

func encodeUTF16NullTerminated(s string) []byte {
	b := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func TestWalkTaskCacheTree(t *testing.T) {
	b := reghivetest.NewBuilder()

	idVal := b.AddValue("Id", encodeUTF16NullTerminated(`{11111111-1111-1111-1111-111111111111}`), 1)
	leaf := b.AddKey("Bar", nil, []uint32{idVal})
	folder := b.AddKey("Foo", []uint32{leaf}, nil) // carpeta: sin valor Id
	root := b.AddKey("Tree", []uint32{folder}, nil)

	data := b.Build(root)
	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	treeKey, err := h.OpenKey("")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}

	got, err := WalkTaskCacheTree(treeKey)
	if err != nil {
		t.Fatalf("WalkTaskCacheTree: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1: %+v", len(got), got)
	}
	if got[0].RelPath != `Foo\Bar` {
		t.Errorf(`RelPath = %q, want "Foo\Bar"`, got[0].RelPath)
	}
	if got[0].ID != `{11111111-1111-1111-1111-111111111111}` {
		t.Errorf("ID = %q", got[0].ID)
	}
}

func TestWalkTaskCacheTreeEmptyTree(t *testing.T) {
	b := reghivetest.NewBuilder()
	root := b.AddKey("Tree", nil, nil)
	data := b.Build(root)
	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	treeKey, _ := h.OpenKey("")
	got, err := WalkTaskCacheTree(treeKey)
	if err != nil {
		t.Fatalf("WalkTaskCacheTree: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got = %+v, want empty", got)
	}
}
