package ui

import (
	"errors"
	"strings"
)

// ErrNotRevealable indica que la ruta no corresponde a algo que el explorador
// pueda mostrar.
var ErrNotRevealable = errors.New("la ruta no apunta a un archivo del disco")

// RevealablePath reporta si una ruta tiene forma de ubicación real del disco.
//
// Muchos artefactos no son archivos: una tarea programada es "Microsoft\
// Windows\...", un servicio es un nombre del registro, y el MFT devuelve
// "\<sin-resolver>\..." cuando no logra reconstruir el directorio padre.
// Ofrecer un botón de carpeta para esos casos sería prometer algo que no se
// puede cumplir.
func RevealablePath(path string) bool {
	p := strings.TrimSpace(path)
	if p == "" {
		return false
	}
	if strings.Contains(p, "<sin-resolver>") {
		return false
	}
	// Rutas con salto de línea o nulos no vienen de un escaneo sano.
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	// Unidad con letra ("C:\...") o ruta UNC ("\\servidor\...").
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}
