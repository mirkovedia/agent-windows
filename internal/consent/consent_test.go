package consent

import (
	"bytes"
	"strings"
	"testing"
)

func TestPromptAcceptsYes(t *testing.T) {
	in := strings.NewReader("si\n")
	var out bytes.Buffer
	accepted, at, err := Prompt(in, &out)
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
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
	accepted, _, err := Prompt(strings.NewReader("no\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("un 'no' explícito no es un error de lectura: %v", err)
	}
	if accepted {
		t.Fatal("esperaba accepted=false con 'no'")
	}
}

// TestPromptEOFIsAnError distingue "no pude leer la respuesta" de "el jugador
// dijo que no". Sin esta distinción, ejecutar el agente sin stdin interactivo
// (p. ej. lanzado desde el Explorador) se reporta como consentimiento
// rechazado, que es engañoso.
func TestPromptEOFIsAnError(t *testing.T) {
	accepted, _, err := Prompt(strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("esperaba error cuando no se puede leer la respuesta")
	}
	if accepted {
		t.Fatal("sin respuesta legible no se puede asumir aceptación")
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
