//go:build windows

// internal/winfs/usn/usn_windows.go
package usn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows (no debería
// dispararse aquí).
var ErrUnsupported = errors.New("USN journal solo disponible en Windows")

// Entry es un Record enriquecido con ruta completa y flag de sospecha.
type Entry struct {
	Record
	FullPath   string
	Suspicious bool
}

// FSCTL codes (winioctl.h).
const (
	fsctlQueryUsnJournal = 0x000900f4
	fsctlEnumUsnData     = 0x000900b3
	fsctlReadUsnJournal  = 0x000900bb
)

// ReadJournal abre el volumen, construye el mapa de padres y devuelve los
// eventos USN relevantes con ruta resuelta.
func ReadJournal(ctx context.Context, volume string) ([]Entry, error) {
	pathPtr, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return nil, fmt.Errorf("path de volumen inválido %q: %w", volume, err)
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("abrir %s: %w", volume, err)
	}
	defer windows.CloseHandle(h)

	journalID, err := queryJournal(h)
	if err != nil {
		return nil, err
	}
	parentMap, err := enumParents(ctx, h)
	if err != nil {
		return nil, err
	}
	return readRecords(ctx, h, journalID, parentMap)
}

// queryJournal devuelve el UsnJournalID (offset 0 del USN_JOURNAL_DATA_V0).
func queryJournal(h windows.Handle) (uint64, error) {
	out := make([]byte, 80)
	var ret uint32
	err := windows.DeviceIoControl(h, fsctlQueryUsnJournal,
		nil, 0, &out[0], uint32(len(out)), &ret, nil)
	if err != nil {
		return 0, fmt.Errorf("QUERY_USN_JOURNAL (¿journal inactivo?): %w", err)
	}
	return binary.LittleEndian.Uint64(out[0:8]), nil
}

// enumParents recorre ENUM_USN_DATA acumulando FileRef -> {nombre, padre}.
func enumParents(ctx context.Context, h windows.Handle) (map[uint64]ParentEntry, error) {
	parentMap := make(map[uint64]ParentEntry)
	// MFT_ENUM_DATA_V0: StartFileReferenceNumber(8) + LowUsn(8) + HighUsn(8).
	in := make([]byte, 24)
	binary.LittleEndian.PutUint64(in[8:16], 0)                   // LowUsn
	binary.LittleEndian.PutUint64(in[16:24], 0xFFFFFFFFFFFFFFFF) // HighUsn
	out := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return parentMap, ctx.Err()
		default:
		}
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlEnumUsnData,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			// ERROR_HANDLE_EOF marca el fin de la enumeración.
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return parentMap, fmt.Errorf("ENUM_USN_DATA: %w", err)
		}
		if ret <= 8 {
			break
		}
		// Los primeros 8 bytes son el NextFileReferenceNumber que siembra la siguiente llamada de enumeración.
		next := binary.LittleEndian.Uint64(out[0:8])
		pos := 8
		for pos < int(ret) {
			rec, n, perr := parseRecord(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			if perr == nil {
				parentMap[rec.FileRef] = ParentEntry{Name: rec.FileName, ParentRef: rec.ParentRef}
			}
			pos += n
		}
		binary.LittleEndian.PutUint64(in[0:8], next)
	}
	return parentMap, nil
}

// readRecords lee el journal desde el inicio y filtra/resuelve los relevantes.
func readRecords(ctx context.Context, h windows.Handle, journalID uint64, parentMap map[uint64]ParentEntry) ([]Entry, error) {
	// READ_USN_JOURNAL_DATA_V0: StartUsn(8) + ReasonMask(4) + ReturnOnlyOnClose(4)
	// + Timeout(8) + BytesToWaitFor(8) + UsnJournalID(8) = 40 bytes.
	in := make([]byte, 40)
	binary.LittleEndian.PutUint32(in[8:12], relevantReasonMask) // ReasonMask
	binary.LittleEndian.PutUint64(in[32:40], journalID)
	out := make([]byte, 64*1024)

	var entries []Entry
	var startUsn int64
	for {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}
		binary.LittleEndian.PutUint64(in[0:8], uint64(startUsn))
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlReadUsnJournal,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			return entries, fmt.Errorf("READ_USN_JOURNAL: %w", err)
		}
		if ret <= 8 {
			break // sin más records
		}
		nextUsn := int64(binary.LittleEndian.Uint64(out[0:8]))
		pos := 8
		for pos < int(ret) {
			rec, n, perr := parseRecord(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			pos += n
			if perr != nil {
				continue
			}
			if !reasonIsRelevant(rec.Reason) {
				continue
			}
			suspicious := fsforensic.IsSuspiciousName(rec.FileName)
			if !fsforensic.HasForensicExtension(rec.FileName) && !suspicious {
				continue
			}
			entries = append(entries, Entry{
				Record:     rec,
				FullPath:   resolvePath(parentMap, rec.ParentRef, rec.FileName),
				Suspicious: suspicious,
			})
		}
		if nextUsn == startUsn {
			break
		}
		startUsn = nextUsn
	}
	return entries, nil
}
