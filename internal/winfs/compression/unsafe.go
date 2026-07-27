//go:build windows

package compression

import "unsafe"

// unsafePtr expone un puntero como unsafe.Pointer para las llamadas syscall.
func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
