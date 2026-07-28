package vss

import "testing"

func TestParseShadowIDFromWmic(t *testing.T) {
	out := `Ejecutando (Win32_ShadowCopy)->create()
Método de ejecución correcto.
Parámetros de salida:
instance of __PARAMETERS
{
	ReturnValue = 0;
	ShadowID = "{A1B2C3D4-0000-1111-2222-334455667788}";
};`
	id, err := parseShadowID(out)
	if err != nil {
		t.Fatalf("parseShadowID error: %v", err)
	}
	if id != "{A1B2C3D4-0000-1111-2222-334455667788}" {
		t.Fatalf("id = %q", id)
	}
}

func TestParseShadowIDMissing(t *testing.T) {
	if _, err := parseShadowID("ReturnValue = 1;"); err == nil {
		t.Fatal("esperaba error cuando no hay ShadowID")
	}
}
