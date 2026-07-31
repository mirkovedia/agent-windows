package consent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// ErrNoInput indica que no se pudo leer una respuesta del jugador (entrada
// cerrada o no interactiva). Es distinto de un rechazo explícito: nadie dijo
// que no, simplemente no había con quién hablar.
var ErrNoInput = errors.New("no se pudo leer la respuesta del jugador")

// Prompt muestra el resumen y espera la aceptación explícita del jugador.
// Devuelve ErrNoInput si la entrada no es legible; en ese caso el llamador debe
// tratarlo como un problema de ejecución, no como un rechazo.
func Prompt(in io.Reader, out io.Writer) (bool, time.Time, error) {
	for _, line := range CollectionSummary() {
		fmt.Fprintln(out, line)
	}
	fmt.Fprint(out, "\n¿Aceptás la revisión? (si/no): ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, time.Time{}, fmt.Errorf("%w: %v", ErrNoInput, err)
		}
		return false, time.Time{}, ErrNoInput
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer == "si" || answer == "sí" || answer == "s" {
		return true, time.Now(), nil
	}
	return false, time.Time{}, nil
}

// HashIdentifier anonimiza un ID de hardware con SHA-256(nonce||raw). Usar el
// nonce de sesión como salt evita correlacionar la misma máquina entre sesiones.
func HashIdentifier(nonce, raw string) string {
	sum := sha256.Sum256([]byte(nonce + raw))
	return hex.EncodeToString(sum[:])
}
