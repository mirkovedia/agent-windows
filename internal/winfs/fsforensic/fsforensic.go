package fsforensic

import (
	"path/filepath"
	"strings"
	"unicode"
)

// forensicExts son las extensiones de ejecutables/scripts que se retienen.
var forensicExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".bat": true, ".ps1": true,
	".cmd": true, ".vbs": true, ".scr": true, ".msi": true,
}

// strongMarkers son marcadores largos e inequívocos: ninguna palabra legítima
// los contiene, así que se buscan como substring. Eso los hace robustos frente
// a nombres sin separadores ("aimbotloader.exe").
var strongMarkers = []string{"cheat", "aimbot", "ccleaner", "bleachbit"}

// weakMarkers son marcadores cortos o frecuentes como fragmento de palabras
// legítimas, así que solo cuentan como token completo. Buscarlos por substring
// producía falsos positivos masivos: "esp" matchea "response" y "namespace",
// "loader" matchea "uploader" y "downloader", "hook" matchea "pyproject-hooks".
// "injector" figura aparte de "inject" porque el matcheo es de token exacto.
var weakMarkers = []string{
	"inject", "injector", "loader", "bypass", "macro", "esp", "hook", "wipe",
}

// msPublicKeyToken es el token de clave pública de Microsoft presente en el
// nombre de todo componente del almacén WinSxS.
const msPublicKeyToken = "_31bf3856ad364e35_"

// winsxsPrefixes son los prefijos de arquitectura del almacén de componentes.
var winsxsPrefixes = []string{
	"amd64_microsoft-", "wow64_microsoft-", "x86_microsoft-", "msil_microsoft-",
}

// HasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func HasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// IsSystemComponent reporta si el nombre corresponde a un componente del
// almacén WinSxS de Windows. Windows Update borra y reemplaza estos archivos de
// forma rutinaria, y sus nombres contienen palabras como "loader", "inject" o
// "hook" por motivos legítimos.
//
// Se identifica por el nombre y no por la ruta a propósito: la reconstrucción
// del directorio padre desde el MFT falla a menudo (rutas "<sin-resolver>"),
// así que una allowlist por ruta no los alcanzaría.
func IsSystemComponent(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, msPublicKeyToken) {
		return true
	}
	for _, p := range winsxsPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// IsSuspiciousName reporta si el nombre contiene un marcador sospechoso, de
// cualquiera de los dos niveles. Los componentes de sistema quedan excluidos.
func IsSuspiciousName(name string) bool {
	return HasStrongMarker(name) || hasWeakMarker(name)
}

// HasStrongMarker reporta si el nombre contiene un marcador inequívoco
// (substring). Los llamadores lo usan para distinguir el peso de la evidencia:
// un marcador fuerte justifica más severidad que uno débil.
func HasStrongMarker(name string) bool {
	if IsSystemComponent(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, m := range strongMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// hasWeakMarker reporta si algún token del nombre es exactamente un marcador
// ambiguo. Es evidencia floja: "run-hook.cmd" y "esp.dll" matchean igual, y el
// primero es un script de desarrollo cualquiera.
func hasWeakMarker(name string) bool {
	if IsSystemComponent(name) {
		return false
	}
	for _, tk := range tokenize(name) {
		for _, m := range weakMarkers {
			if tk == m {
				return true
			}
		}
	}
	return false
}

// tokenize parte un nombre en tokens en minúscula, cortando por separadores
// (-, _, ., espacio) , por separadores de ruta (\, /, :) y por cambios de
// camelCase. Así "logUploaderSettings.ini" da [log uploader settings ini] y el
// marcador "loader" deja de matchear "Uploader".
//
// Corta por ruta porque los llamadores pasan el path completo del artefacto,
// no solo el nombre del archivo: sin eso "C:\...\Prefetch\INJECTOR.EXE" nunca
// produciría "injector" como token propio.
func tokenize(name string) []string {
	var tokens []string
	var cur []rune

	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '-' || r == '_' || r == '.' || r == ' ' ||
			r == '\\' || r == '/' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]):
			// Frontera camelCase: "logUploader" -> "log" + "Uploader".
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return tokens
}
