// internal/winfs/reghive/reghivetest/builder_test.go
package reghivetest

import (
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

func TestBuilderRoundTrip(t *testing.T) {
	b := NewBuilder()
	val := b.AddValue("Greeting", []byte("hi"), 1) // 2 bytes: camino inline
	child := b.AddKey("Child", nil, []uint32{val})
	root := b.AddKey("Root", []uint32{child}, nil)
	data := b.Build(root)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	rootKey, err := h.OpenKey("")
	if err != nil {
		t.Fatalf(`OpenKey(""): %v`, err)
	}
	if rootKey.Name() != "Root" {
		t.Fatalf("Name() = %q, want Root", rootKey.Name())
	}
	childKey, err := h.OpenKey("Child")
	if err != nil {
		t.Fatalf("OpenKey(Child): %v", err)
	}
	got, _, err := childKey.Value("Greeting")
	if err != nil {
		t.Fatalf("Value(Greeting): %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("Value = %q, want hi", string(got))
	}
}

func TestBuilderValueLongerThanFourBytes(t *testing.T) {
	b := NewBuilder()
	val := b.AddValue("Big", []byte("more than four bytes"), 1) // camino no-inline
	root := b.AddKey("Root", nil, []uint32{val})
	data := b.Build(root)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	rootKey, _ := h.OpenKey("")
	got, _, err := rootKey.Value("Big")
	if err != nil {
		t.Fatalf("Value(Big): %v", err)
	}
	if string(got) != "more than four bytes" {
		t.Fatalf("Value = %q", string(got))
	}
}
