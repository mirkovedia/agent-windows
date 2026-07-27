package consent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// CollectionSummary describe, en lenguaje claro, exactamente qué recolecta el
// agente. Nunca contenido de archivos, credenciales, historial ni mensajes.
func CollectionSummary() []string {
	return []string{
		"El agente recolecta SOLO metadatos forenses, nunca el contenido de tus archivos:",
		"  - Nombres, hashes y timestamps de programas ejecutados (Prefetch, BAM, ShimCache, AmCache).",
		"  - Rastros de borrado de archivos (historial del sistema de archivos).",
		"  - Configuración de emuladores y macros de control.",
		"NO se leen: documentos, fotos, mensajes, contraseñas, cookies ni historial de navegación.",
		"Los identificadores de hardware se anonimizan antes de salir del equipo.",
	}
}

// Prompt muestra el resumen y espera la aceptación explícita del jugador.
func Prompt(in io.Reader, out io.Writer) (bool, time.Time) {
	for _, line := range CollectionSummary() {
		fmt.Fprintln(out, line)
	}
	fmt.Fprint(out, "\n¿Aceptás la revisión? (si/no): ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false, time.Time{}
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer == "si" || answer == "sí" || answer == "s" {
		return true, time.Now()
	}
	return false, time.Time{}
}

// HashIdentifier anonimiza un ID de hardware con SHA-256(nonce||raw). Usar el
// nonce de sesión como salt evita correlacionar la misma máquina entre sesiones.
func HashIdentifier(nonce, raw string) string {
	sum := sha256.Sum256([]byte(nonce + raw))
	return hex.EncodeToString(sum[:])
}
