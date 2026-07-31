package verdict

import "testing"

func TestPreviewMarksStrongSignalNotable(t *testing.T) {
	got := Preview(art("mft_timestomp", `C:\x.exe`, nil))
	if !got.Notable {
		t.Fatal("una señal fuerte debe mostrarse en vivo")
	}
	if got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH", got.Severity)
	}
	if got.Title == "" {
		t.Fatal("el hallazgo en vivo necesita título legible")
	}
}

// TestPreviewHidesNeutralNoise cubre el motivo de existir de Notable: sin él,
// los ~1000 artefactos de prefetch taparían las señales que importan.
func TestPreviewHidesNeutralNoise(t *testing.T) {
	got := Preview(art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil))
	if got.Notable {
		t.Fatal("la evidencia neutra no debe aparecer en la vista en vivo")
	}
	if got.Severity != SevInfo {
		t.Fatalf("Severity = %s, want INFO", got.Severity)
	}
}

// TestPreviewAppliesNameEscalation verifica que la vista en vivo use las
// mismas reglas que el motor: un neutro con nombre sospechoso sí se muestra.
func TestPreviewAppliesNameEscalation(t *testing.T) {
	got := Preview(art("prefetch", `C:\Windows\Prefetch\INJECTOR.EXE-2.pf`, nil))
	if !got.Notable {
		t.Fatal("un prefetch sospechoso sí debe mostrarse en vivo")
	}
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
}

func TestPreviewUnknownTypeIsNotNotable(t *testing.T) {
	got := Preview(art("colector_del_futuro", "x", nil))
	if got.Notable {
		t.Fatal("un tipo desconocido no puede ser notable por sí solo")
	}
}
