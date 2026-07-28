//go:build !windows

package mft

import (
	"context"
	"errors"
)

// ErrUnsupported se devuelve al intentar leer el MFT fuera de Windows.
var ErrUnsupported = errors.New("MFT solo disponible en Windows")

// Finding es una detección de timestomping lista para reportar.
type Finding struct {
	FullPath string
	FileName string
	SI       Timestamps
	FN       Timestamps
	Verdict  Verdict
}

// ScanTimestomp no está soportado fuera de Windows.
func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error) {
	return nil, ErrUnsupported
}
