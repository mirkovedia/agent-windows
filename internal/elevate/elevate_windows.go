//go:build windows

// Package elevate relanza el ejecutable actual solicitando privilegios de
// administrador. Sin esto el usuario tiene que saber usar "Ejecutar como
// administrador", que es exactamente la fricción que la app quiere eliminar.
package elevate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ErrUnsupported existe por simetría con el stub de otras plataformas.
var ErrUnsupported = errors.New("elevación solo disponible en Windows")

// Relaunch vuelve a lanzar el ejecutable actual pidiendo elevación (UAC).
//
// El proceso nuevo es independiente: el llamador debe terminar de inmediato
// con os.Exit(0), o quedan dos instancias corriendo. Si el usuario rechaza el
// diálogo de UAC, Windows devuelve ERROR_CANCELLED y esta función retorna
// error, de modo que el llamador pueda explicar por qué no se puede seguir.
func Relaunch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	// Se propagan los argumentos originales para que la instancia elevada
	// conserve el modo pedido (por ejemplo -console).
	args, err := windows.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	if err != nil {
		return err
	}
	cwd, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	// SW_NORMAL: la ventana del proceso elevado se muestra normalmente.
	return windows.ShellExecute(0, verb, file, args, cwd, windows.SW_NORMAL)
}
