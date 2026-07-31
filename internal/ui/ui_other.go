//go:build !windows

package ui

// Run no está soportado fuera de Windows. Existe para que el paquete compile
// y se pueda testear la parte pura (eventos, ensamblado del HTML) en cualquier
// host de CI.
func Run(opts Options) error { return ErrWebViewUnavailable }
