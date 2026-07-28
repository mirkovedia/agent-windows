package usn

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

// relevantReasonMask agrega las razones USN forensicamente significativas.
const relevantReasonMask = ReasonDataOverwrite | ReasonDataTruncation |
	ReasonFileCreate | ReasonFileDelete | ReasonRenameOldName | ReasonRenameNewName

// hasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func hasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// isSuspiciousName reporta si el nombre contiene un marcador sospechoso.
func isSuspiciousName(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range suspiciousMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// reasonIsRelevant reporta si la máscara de razones incluye alguna relevante.
func reasonIsRelevant(reason uint32) bool {
	return reason&relevantReasonMask != 0
}
