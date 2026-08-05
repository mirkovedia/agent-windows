//go:build !windows

// internal/winfs/ntfs/ntfs_other.go
package ntfs

import (
	"context"
	"errors"

	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
)

// ErrUnsupported se devuelve al intentar acceso raw NTFS fuera de Windows.
var ErrUnsupported = errors.New("acceso raw NTFS solo disponible en Windows")

// DeletedEntry es una entrada borrada recuperada del MFT.
type DeletedEntry struct {
	FullPath string
	FileName string
	SI       winmft.Timestamps
	FN       winmft.Timestamps
	Verdict  winmft.Verdict
	RecordNo uint64
}

// ScanDeleted no está soportado fuera de Windows.
func ScanDeleted(ctx context.Context, volume string, onProgress func(done, total int64)) ([]DeletedEntry, error) {
	return nil, ErrUnsupported
}
