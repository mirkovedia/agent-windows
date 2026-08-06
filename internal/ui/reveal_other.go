//go:build !windows

package ui

// Reveal no está soportado fuera de Windows.
func Reveal(path string) error { return ErrNotRevealable }
