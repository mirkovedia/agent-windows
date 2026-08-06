//go:build windows

package ui

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Reveal abre el explorador de Windows mostrando la ubicación de path.
//
// Si el archivo existe se lo deja seleccionado; si ya no está (el caso normal
// de un artefacto borrado recuperado del MFT) se abre el directorio que lo
// contenía, que sigue siendo información útil para quien revisa.
func Reveal(path string) error {
	if !RevealablePath(path) {
		return ErrNotRevealable
	}
	clean := filepath.Clean(path)

	if _, err := os.Stat(clean); err == nil {
		// exec.Command no pasa por una shell, así que la ruta no puede
		// inyectar comandos por más rara que sea.
		// explorer.exe devuelve código 1 incluso cuando abre bien, así que
		// su código de salida no se interpreta como fallo.
		_ = exec.Command("explorer.exe", "/select,"+clean).Run()
		return nil
	}

	dir := filepath.Dir(clean)
	if _, err := os.Stat(dir); err != nil {
		return ErrNotRevealable
	}
	_ = exec.Command("explorer.exe", dir).Run()
	return nil
}
