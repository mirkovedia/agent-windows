package fsforensic

import (
	"path/filepath"
	"strings"
)

// forensicExts son las extensiones de ejecutables/scripts que se retienen.
var forensicExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".bat": true, ".ps1": true,
	".cmd": true, ".vbs": true, ".scr": true, ".msi": true,
}

// suspiciousMarkers son subcadenas que suben la sospecha de un nombre (heurística
// para severidad; hoy solo marca el flag, la severidad real llega en Fase 4).
var suspiciousMarkers = []string{
	"cheat", "inject", "loader", "bypass", "aimbot", "macro",
	"esp", "hook", "wipe", "ccleaner", "bleachbit",
}

// HasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func HasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// IsSuspiciousName reporta si el nombre contiene un marcador sospechoso.
func IsSuspiciousName(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range suspiciousMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
