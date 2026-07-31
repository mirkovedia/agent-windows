package elevate

import (
	"errors"
	"testing"
)

// TestErrUnsupportedExists garantiza que ambas plataformas expongan el error,
// para que el llamador pueda distinguir "acá no puedo elevar" de un fallo real
// del diálogo de UAC.
func TestErrUnsupportedExists(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported no debe ser nil")
	}
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Fatal("ErrUnsupported debe ser comparable con errors.Is")
	}
}
