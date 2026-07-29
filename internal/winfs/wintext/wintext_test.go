// internal/winfs/wintext/wintext_test.go
package wintext

import "testing"

func TestDecodeUTF16StopsAtNull(t *testing.T) {
	// "AB" en UTF-16LE seguido de terminador nulo y basura tras el terminador.
	b := []byte{'A', 0x00, 'B', 0x00, 0x00, 0x00, 'X', 0x00}
	got := DecodeUTF16(b)
	if got != "AB" {
		t.Fatalf("DecodeUTF16 = %q, want %q", got, "AB")
	}
}

func TestDecodeUTF16NoTerminator(t *testing.T) {
	// Sin terminador nulo: decodifica todo el buffer.
	b := []byte{'H', 0x00, 'I', 0x00}
	got := DecodeUTF16(b)
	if got != "HI" {
		t.Fatalf("DecodeUTF16 = %q, want %q", got, "HI")
	}
}

func TestDecodeUTF16Empty(t *testing.T) {
	if got := DecodeUTF16(nil); got != "" {
		t.Fatalf("DecodeUTF16(nil) = %q, want empty", got)
	}
}
