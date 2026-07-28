package usn

import "testing"

func TestHasForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"cheat.exe":        true,
		"driver.SYS":       true,
		"script.ps1":       true,
		"documento.docx":   false,
		"foto.jpg":         false,
		"sinextension":     false,
	}
	for name, want := range cases {
		if got := hasForensicExtension(name); got != want {
			t.Errorf("hasForensicExtension(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsSuspiciousName(t *testing.T) {
	if !isSuspiciousName("FreeFire_Injector.exe") {
		t.Error("esperaba sospechoso para nombre con 'inject'")
	}
	if isSuspiciousName("notepad.exe") {
		t.Error("notepad.exe no debería ser sospechoso")
	}
}

func TestReasonIsRelevant(t *testing.T) {
	if !reasonIsRelevant(ReasonFileDelete) {
		t.Error("FileDelete debería ser relevante")
	}
	if reasonIsRelevant(0x80000000) { // USN_REASON_CLOSE, no relevante por sí solo
		t.Error("CLOSE-solo no debería ser relevante")
	}
}
