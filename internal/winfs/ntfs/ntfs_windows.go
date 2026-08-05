//go:build windows

// internal/winfs/ntfs/ntfs_windows.go
package ntfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/telagem/agent-windows/internal/winfs/fsforensic"
	winmft "github.com/telagem/agent-windows/internal/winfs/mft"
	"github.com/telagem/agent-windows/internal/winfs/ntfspath"
)

// ErrUnsupported se mantiene por paridad con la build no-Windows.
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

const (
	chunkTarget = 1 << 20 // objetivo ~1 MB por lectura

	// maxRecords acota el barrido ante MFT patológicos/corruptos.
	maxRecords = 8_000_000

	// mftEntryMask aísla el nº de entrada MFT (48 bits bajos) del file reference.
	mftEntryMask = 0x0000FFFFFFFFFFFF
)

// pendingEntry es un borrado candidato cuyo path se resuelve tras completar el mapa de padres.
type pendingEntry struct {
	fileName  string
	parentRef uint64
	si, fn    winmft.Timestamps
	verdict   winmft.Verdict
	recordNo  uint64
}

// ScanDeleted abre el volumen en crudo, ubica el $MFT vía boot sector + data runs,
// barre todos los registros y recupera los borrados (InUse=0) que son forenses.
// ScanDeleted recorre la MFT del volumen buscando entradas borradas.
//
// onProgress, si no es nil, recibe el avance en bytes de MFT leídos sobre el
// total. Recorrer la MFT entera lleva decenas de segundos: sin este aviso la
// interfaz no tiene forma de mostrar que algo está pasando.
func ScanDeleted(ctx context.Context, volume string, onProgress func(done, total int64)) ([]DeletedEntry, error) {
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

	// 1. Boot sector → geometría.
	sector := make([]byte, 512)
	if err := readAt(h, 0, sector); err != nil {
		return nil, fmt.Errorf("leer boot sector: %w", err)
	}
	boot, err := ParseBootSector(sector)
	if err != nil {
		return nil, err
	}

	// 2. Registro 0 ($MFT) → data runs de su $DATA.
	rec0 := make([]byte, boot.BytesPerRecord)
	if err := readAt(h, int64(boot.MFTCluster)*int64(boot.ClusterSize), rec0); err != nil {
		return nil, fmt.Errorf("leer registro $MFT: %w", err)
	}
	fixed, err := winmft.ApplyFixup(rec0)
	if err != nil {
		return nil, fmt.Errorf("fixup del $MFT: %w", err)
	}
	runBytes, err := nonResidentDataRuns(fixed)
	if err != nil {
		return nil, err
	}
	extents, err := DecodeDataRuns(runBytes)
	if err != nil {
		return nil, err
	}

	// 3. Barrido en streaming a lo largo de los extents.
	parentMap := make(map[uint64]ntfspath.ParentEntry)
	var pending []pendingEntry

	recSize := boot.BytesPerRecord
	recsPerChunk := chunkTarget / recSize
	if recsPerChunk == 0 {
		recsPerChunk = 1
	}
	readSize := recsPerChunk * recSize
	buf := make([]byte, readSize)
	carry := make([]byte, 0, recSize) // sobrante de registro que cruza un límite de lectura
	var ordinal uint64

	process := func(recBuf []byte, ord uint64) {
		rec, err := winmft.ParseRecord(recBuf)
		if err != nil {
			return // slot inválido, nunca usado o basura: se salta en silencio
		}
		seq := binary.LittleEndian.Uint16(recBuf[0x10:0x12])
		ownRef := uint64(seq)<<48 | (ord & mftEntryMask)

		// Directorios vivos alimentan el mapa de padres para reconstruir rutas.
		if rec.InUse && rec.IsDir && rec.HasFN {
			parentMap[ownRef] = ntfspath.ParentEntry{Name: rec.FileName, ParentRef: rec.ParentRef}
			return
		}
		// Candidatos: borrados, con nombre, forenses.
		if rec.InUse || !rec.HasFN {
			return
		}
		if !fsforensic.HasForensicExtension(rec.FileName) && !fsforensic.IsSuspiciousName(rec.FileName) {
			return
		}
		pending = append(pending, pendingEntry{
			fileName:  rec.FileName,
			parentRef: rec.ParentRef,
			si:        rec.SI,
			fn:        rec.FN,
			verdict:   winmft.DetectTimestomp(rec.SI, rec.FN),
			recordNo:  ord,
		})
	}

	finish := func() []DeletedEntry {
		out := make([]DeletedEntry, 0, len(pending))
		for _, p := range pending {
			full := ntfspath.ResolvePath(parentMap, p.parentRef, p.fileName)
			// Windows Update borra y reemplaza miles de archivos del almacén
			// de componentes en cada actualización. El nombre suelto no los
			// delata ("oobeldr.exe", "ci.dll"): el token de Microsoft vive en
			// el directorio, así que este filtro solo puede aplicarse acá,
			// con la ruta ya reconstruida.
			if fsforensic.IsSystemComponent(full) {
				continue
			}
			out = append(out, DeletedEntry{
				FullPath: full,
				FileName: p.fileName,
				SI:       p.si,
				FN:       p.fn,
				Verdict:  p.verdict,
				RecordNo: p.recordNo,
			})
		}
		return out
	}

	// Total a recorrer, para poder informar avance como fracción.
	var mftTotal int64
	for _, ext := range extents {
		mftTotal += int64(ext.Length) * int64(boot.ClusterSize)
	}
	var mftDone int64

scan:
	for _, ext := range extents {
		extentBytes := int64(ext.Length) * int64(boot.ClusterSize)
		diskOff := int64(ext.StartLCN) * int64(boot.ClusterSize)
		for pos := int64(0); pos < extentBytes; {
			select {
			case <-ctx.Done():
				return finish(), ctx.Err()
			default:
			}
			toRead := int64(readSize)
			if rem := extentBytes - pos; rem < toRead {
				toRead = rem
			}
			if err := readAt(h, diskOff+pos, buf[:toRead]); err != nil {
				return finish(), fmt.Errorf("leer MFT en offset %d: %w", diskOff+pos, err)
			}
			pos += toRead
			mftDone += toRead
			if onProgress != nil {
				onProgress(mftDone, mftTotal)
			}

			// Combinar el sobrante del bloque anterior con lo recién leído.
			var data []byte
			if len(carry) > 0 {
				data = make([]byte, 0, len(carry)+int(toRead))
				data = append(data, carry...)
				data = append(data, buf[:toRead]...)
				carry = carry[:0]
			} else {
				data = buf[:toRead]
			}

			i := 0
			for ; i+recSize <= len(data); i += recSize {
				process(data[i:i+recSize], ordinal)
				ordinal++
				if ordinal >= maxRecords {
					break scan
				}
			}
			if rem := len(data) - i; rem > 0 {
				carry = append(carry[:0], data[i:]...)
			}
		}
	}
	return finish(), nil
}

// readAt lee len(buf) bytes desde offset usando un OVERLAPPED (posición explícita),
// lo que permite leer por offset en un handle de volumen sincrónico sin mantener
// un puntero de archivo. offset y len(buf) deben estar alineados a sector.
func readAt(h windows.Handle, offset int64, buf []byte) error {
	var ov windows.Overlapped
	ov.Offset = uint32(offset & 0xFFFFFFFF)
	ov.OffsetHigh = uint32(offset >> 32)
	var done uint32
	if err := windows.ReadFile(h, buf, &done, &ov); err != nil {
		return err
	}
	if int(done) != len(buf) {
		return fmt.Errorf("lectura corta: %d de %d bytes", done, len(buf))
	}
	return nil
}
