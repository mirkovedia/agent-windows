//go:build !windows

// Package elevate relanza el ejecutable actual solicitando privilegios de
// administrador. Sin esto el usuario tiene que saber usar "Ejecutar como
// administrador", que es exactamente la fricción que la app quiere eliminar.
package elevate

import "errors"

// ErrUnsupported indica que la elevación no está disponible en esta plataforma.
var ErrUnsupported = errors.New("elevación solo disponible en Windows")

// Relaunch no está soportado fuera de Windows.
func Relaunch() error { return ErrUnsupported }
