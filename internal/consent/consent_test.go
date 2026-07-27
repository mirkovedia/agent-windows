package consent

import (
	"bytes"
	"strings"
	"testing"
)

func TestPromptAcceptsYes(t *testing.T) {
	in := strings.NewReader("si\n")
	var out bytes.Buffer
	accepted, at := Prompt(in, &out)
	if !accepted {
		t.Fatal("esperaba accepted=true con 'si'")
	}
	if at.IsZero() {
		t.Fatal("esperaba timestamp de consentimiento no cero")
	}
	if !strings.Contains(out.String(), "metadatos") {
		t.Fatal("el resumen debería explicar que solo se recolectan metadatos")
	}
}

func TestPromptRejectsOther(t *testing.T) {
	accepted, _ := Prompt(strings.NewReader("no\n"), &bytes.Buffer{})
	if accepted {
		t.Fatal("esperaba accepted=false con 'no'")
	}
}

func TestHashIdentifierDependsOnNonce(t *testing.T) {
	h1 := HashIdentifier("nonce-1", "DISK-SERIAL-XYZ")
	h2 := HashIdentifier("nonce-2", "DISK-SERIAL-XYZ")
	if h1 == h2 {
		t.Fatal("el mismo ID con distinto nonce no debe ser correlacionable")
	}
	if h1 == "DISK-SERIAL-XYZ" || len(h1) != 64 {
		t.Fatalf("el hash debería ser SHA-256 hex (64 chars), got %q", h1)
	}
}
