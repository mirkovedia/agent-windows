package fsforensic

import "testing"

func TestHasForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"cheat.exe":      true,
		"driver.SYS":     true,
		"script.ps1":     true,
		"documento.docx": false,
		"foto.jpg":       false,
		"sinextension":   false,
	}
	for name, want := range cases {
		if got := HasForensicExtension(name); got != want {
			t.Errorf("HasForensicExtension(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsSuspiciousName(t *testing.T) {
	if !IsSuspiciousName("FreeFire_Injector.exe") {
		t.Error("esperaba sospechoso para nombre con 'inject'")
	}
	if IsSuspiciousName("notepad.exe") {
		t.Error("notepad.exe no debería ser sospechoso")
	}
}
