//go:build windows

package mft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	"github.com/telagem/agent-windows/internal/winfs/ntfspath"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows (no debería
// dispararse aquí).
var ErrUnsupported = errors.New("MFT solo disponible en Windows")

// Finding es una detección de timestomping lista para reportar.
type Finding struct {
	FullPath string
	FileName string
	SI       Timestamps
	FN       Timestamps
	Verdict  Verdict
}

// FSCTL codes (winioctl.h).
const (
	fsctlEnumUsnData       = 0x000900b3
	fsctlGetNtfsFileRecord = 0x00090068
)

// mftEntryMask aísla el nº de entrada MFT (48 bits bajos) del file reference,
// ignorando el nº de secuencia en los 16 bits altos.
const mftEntryMask = 0x0000FFFFFFFFFFFF

// ScanTimestomp abre el volumen, enumera el MFT filtrando a archivos forenses y
// evalúa timestomping en cada candidato pidiendo su registro con FSCTL.
func ScanTimestomp(ctx context.Context, volume string) ([]Finding, error) {
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

	parentMap, candidates, err := enumForensic(ctx, h)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, ref := range candidates {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		rec, err := getFileRecord(h, ref)
		if err != nil || !rec.HasSI || !rec.HasFN {
			continue
		}
		v := DetectTimestomp(rec.SI, rec.FN)
		if !v.Stomped {
			continue
		}
		parentRef := parentMap[ref].ParentRef
		findings = append(findings, Finding{
			FullPath: ntfspath.ResolvePath(parentMap, parentRef, rec.FileName),
			FileName: rec.FileName,
			SI:       rec.SI,
			FN:       rec.FN,
			Verdict:  v,
		})
	}
	return findings, nil
}

// enumForensic recorre ENUM_USN_DATA una vez: construye el mapa de padres (para
// resolver rutas) y junta los file refs cuyo nombre pasa el filtro forense.
func enumForensic(ctx context.Context, h windows.Handle) (map[uint64]ntfspath.ParentEntry, []uint64, error) {
	parentMap := make(map[uint64]ntfspath.ParentEntry)
	var candidates []uint64
	// MFT_ENUM_DATA_V0: StartFileReferenceNumber(8) + LowUsn(8) + HighUsn(8).
	in := make([]byte, 24)
	binary.LittleEndian.PutUint64(in[8:16], 0)                   // LowUsn
	binary.LittleEndian.PutUint64(in[16:24], 0xFFFFFFFFFFFFFFFF) // HighUsn
	out := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return parentMap, candidates, ctx.Err()
		default:
		}
		var ret uint32
		err := windows.DeviceIoControl(h, fsctlEnumUsnData,
			&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
		if err != nil {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return parentMap, candidates, fmt.Errorf("ENUM_USN_DATA: %w", err)
		}
		if ret <= 8 {
			break
		}
		next := binary.LittleEndian.Uint64(out[0:8])
		pos := 8
		for pos < int(ret) {
			ref, parentRef, name, n := parseEnumEntry(out[pos:int(ret)])
			if n <= 0 {
				break
			}
			pos += n
			if name == "" {
				continue
			}
			parentMap[ref] = ntfspath.ParentEntry{Name: name, ParentRef: parentRef}
			if fsforensic.HasForensicExtension(name) || fsforensic.IsSuspiciousName(name) {
				candidates = append(candidates, ref)
			}
		}
		binary.LittleEndian.PutUint64(in[0:8], next)
	}
	return parentMap, candidates, nil
}

// parseEnumEntry extrae los campos que necesita la enumeración (fileRef,
// parentRef, nombre) de un USN_RECORD_V2/V3, devolviendo también su longitud
// para avanzar. Es una lectura mínima e intencionalmente local, para no acoplar
// mft al parser completo del journal (paquete usn). n<=0 indica fin/error.
func parseEnumEntry(buf []byte) (fileRef, parentRef uint64, name string, n int) {
	if len(buf) < 4 {
		return 0, 0, "", 0
	}
	recLen := int(binary.LittleEndian.Uint32(buf[0:4]))
	if recLen < 8 || recLen > len(buf) {
		return 0, 0, "", 0
	}
	major := binary.LittleEndian.Uint16(buf[4:6])
	var refOff, parentOff, nameLenOff, nameOffOff int
	switch major {
	case 2:
		refOff, parentOff, nameLenOff, nameOffOff = 0x08, 0x10, 0x38, 0x3A
	case 3:
		refOff, parentOff, nameLenOff, nameOffOff = 0x08, 0x18, 0x48, 0x4A
	default:
		return 0, 0, "", recLen // versión desconocida: saltear
	}
	if nameOffOff+2 > recLen {
		return 0, 0, "", recLen
	}
	fileRef = binary.LittleEndian.Uint64(buf[refOff : refOff+8])
	parentRef = binary.LittleEndian.Uint64(buf[parentOff : parentOff+8])
	nameLen := int(binary.LittleEndian.Uint16(buf[nameLenOff : nameLenOff+2]))
	nameOff := int(binary.LittleEndian.Uint16(buf[nameOffOff : nameOffOff+2]))
	if nameOff+nameLen <= recLen && nameOff+nameLen <= len(buf) {
		name = decodeUTF16(buf[nameOff : nameOff+nameLen])
	}
	return fileRef, parentRef, name, recLen
}

// getFileRecord pide a NTFS el registro MFT de fileRef y lo parsea. FSCTL puede
// devolver el registro en uso de ordinal <= al pedido; si el nº de entrada MFT
// devuelto no coincide, se descarta.
func getFileRecord(h windows.Handle, fileRef uint64) (Record, error) {
	in := make([]byte, 8)
	binary.LittleEndian.PutUint64(in, fileRef)
	// NTFS_FILE_RECORD_OUTPUT_BUFFER: FileReferenceNumber(8) + FileRecordLength(4)
	// + FileRecordBuffer(...). 8 KiB cubre registros de 1024 y 4096 bytes con holgura.
	out := make([]byte, 8192)
	var ret uint32
	err := windows.DeviceIoControl(h, fsctlGetNtfsFileRecord,
		&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil)
	if err != nil {
		return Record{}, fmt.Errorf("GET_NTFS_FILE_RECORD ref %d: %w", fileRef, err)
	}
	if ret < 12 {
		return Record{}, fmt.Errorf("respuesta MFT muy corta: %d", ret)
	}
	gotRef := binary.LittleEndian.Uint64(out[0:8])
	if gotRef&mftEntryMask != fileRef&mftEntryMask {
		return Record{}, errors.New("FSCTL devolvió otro registro (el pedido no está en uso)")
	}
	recLen := int(binary.LittleEndian.Uint32(out[8:12]))
	if recLen <= 0 || 12+recLen > int(ret) {
		return Record{}, errors.New("FileRecordLength fuera de rango")
	}
	return ParseRecord(out[12 : 12+recLen])
}
