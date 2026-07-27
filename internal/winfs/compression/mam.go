//go:build windows

package compression

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

const signatureMAM = "MAM\x04"

// COMPRESSION_FORMAT_XPRESS_HUFF según wdm.h.
const compressionFormatXpressHuff = 0x0004

var (
	modntdll                           = windows.NewLazySystemDLL("ntdll.dll")
	procRtlDecompressBufferEx          = modntdll.NewProc("RtlDecompressBufferEx")
	procRtlGetCompressionWorkSpaceSize = modntdll.NewProc("RtlGetCompressionWorkSpaceSize")
)

// DecompressMAM descomprime un buffer con firma MAM (Xpress Huffman), usado por
// los Prefetch de Win8+. Sin firma, devuelve los datos intactos.
func DecompressMAM(data []byte) ([]byte, error) {
	if len(data) < len(signatureMAM) || string(data[:len(signatureMAM)]) != signatureMAM {
		return data, nil
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("header MAM truncado: %d bytes", len(data))
	}
	uncompressedSize := binary.LittleEndian.Uint32(data[4:8])
	compressed := data[8:]

	var workspaceSize, fragmentSize uint32
	rt, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafePtr(&workspaceSize)),
		uintptr(unsafePtr(&fragmentSize)),
	)
	if rt != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize falló: 0x%x", rt)
	}
	workspace := make([]byte, workspaceSize)
	out := make([]byte, uncompressedSize)
	var finalSize uint32

	rt, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafePtr(&out[0])), uintptr(len(out)),
		uintptr(unsafePtr(&compressed[0])), uintptr(len(compressed)),
		uintptr(unsafePtr(&finalSize)),
		uintptr(unsafePtr(&workspace[0])),
	)
	if rt != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx falló: 0x%x", rt)
	}
	return out[:finalSize], nil
}
