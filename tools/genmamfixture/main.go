//go:build ignore

// Generador de fixtures MAM: comprime un texto con RtlCompressBuffer
// (Xpress Huffman) y antepone el header MAM de 8 bytes, replicando el formato
// de los Prefetch de Win8+. Uso: go run tools/genmamfixture/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	xpressHuff   = 0x0004
	chunkSize    = 4096
	outDir       = `internal\winfs\compression\testdata`
)

func ptr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }

func main() {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	getWS := ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	compress := ntdll.NewProc("RtlCompressBuffer")

	original := []byte("telagem forense: contenido de prueba para round-trip MAM. " +
		"Repetición repetición repetición para dar material al compresor Xpress Huffman.")

	var wsSize, fragSize uint32
	rt, _, _ := getWS.Call(uintptr(xpressHuff), uintptr(ptr(&wsSize)), uintptr(ptr(&fragSize)))
	if rt != 0 {
		panic(fmt.Sprintf("RtlGetCompressionWorkSpaceSize: 0x%x", rt))
	}
	workspace := make([]byte, wsSize)
	compressed := make([]byte, len(original)*2+64)
	var finalSize uint32

	rt, _, _ = compress.Call(
		uintptr(xpressHuff),
		uintptr(ptr(&original[0])), uintptr(len(original)),
		uintptr(ptr(&compressed[0])), uintptr(len(compressed)),
		uintptr(chunkSize),
		uintptr(ptr(&finalSize)),
		uintptr(ptr(&workspace[0])),
	)
	if rt != 0 {
		panic(fmt.Sprintf("RtlCompressBuffer: 0x%x", rt))
	}

	// Header MAM: "MAM\x04" + uint32 LE del tamaño descomprimido.
	header := append([]byte("MAM\x04"), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(original)))
	blob := append(header, compressed[:finalSize]...)

	must(os.WriteFile(outDir+`\sample_mam.bin`, blob, 0644))
	must(os.WriteFile(outDir+`\sample_mam.expected`, original, 0644))
	fmt.Printf("fixture generado: %d bytes originales -> %d comprimidos\n", len(original), finalSize)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
