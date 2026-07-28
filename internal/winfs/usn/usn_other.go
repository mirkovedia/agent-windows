//go:build !windows

// internal/winfs/usn/usn_other.go
package usn

import (
	"context"
	"errors"
)

// ErrUnsupported se devuelve al intentar leer el journal fuera de Windows.
var ErrUnsupported = errors.New("USN journal solo disponible en Windows")

// Entry es un Record enriquecido con ruta completa y flag de sospecha.
type Entry struct {
	Record
	FullPath   string
	Suspicious bool
}

// ReadJournal no está soportado fuera de Windows.
func ReadJournal(ctx context.Context, volume string) ([]Entry, error) {
	return nil, ErrUnsupported
}
