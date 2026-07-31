package ui

import "testing"

func TestRevealablePathAcceptsRealPaths(t *testing.T) {
	ok := []string{
		`C:\Users\mirko\Downloads\algo.exe`,
		`C:/Users/mirko/algo.exe`,
		`D:\Temp\x.sys`,
		`\\servidor\compartido\x.dll`,
	}
	for _, p := range ok {
		if !RevealablePath(p) {
			t.Errorf("RevealablePath(%q) = false, debería aceptarse", p)
		}
	}
}

// TestRevealablePathRejectsNonFiles cubre los artefactos que no son archivos:
// ofrecerles un botón de carpeta sería prometer algo imposible.
func TestRevealablePathRejectsNonFiles(t *testing.T) {
	no := []string{
		"",
		`Microsoft\Windows\Application Experience\AitAgent`, // tarea programada
		"EvilDrv",                        // nombre de servicio
		`\<sin-resolver>\run-hook.cmd`,   // el MFT no resolvió el padre
		"prefetch",                       // nombre de colector
		"C:\nmalicioso",                  // salto de línea
	}
	for _, p := range no {
		if RevealablePath(p) {
			t.Errorf("RevealablePath(%q) = true, no es una ubicación del disco", p)
		}
	}
}

func TestRevealRejectsNonRevealable(t *testing.T) {
	if err := Reveal(`Microsoft\Windows\Foo`); err == nil {
		t.Fatal("esperaba error para una ruta que no es del disco")
	}
}
