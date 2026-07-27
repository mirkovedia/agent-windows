package privilege

import (
	"os"
	"strings"
)

// VMIndicator reporta si la máquina parece una VM/sandbox y por qué.
// Nunca provoca un aborto: es solo contexto para el reporte.
type VMIndicator struct {
	Detected bool
	Reasons  []string
}

// vmArtifactMarkers son fragmentos de path que delatan un hipervisor.
var vmArtifactMarkers = map[string]string{
	`vmmouse.sys`:   "driver de VMware presente",
	`vmhgfs.sys`:    "driver de VMware presente",
	`VMware Tools`:  "VMware Tools instalado",
	`vboxguest.sys`: "driver de VirtualBox presente",
	`VBoxService`:   "VirtualBox Guest Additions instalado",
	`prl_fs.sys`:    "driver de Parallels presente",
	`vmicheartbeat`: "servicio de integración Hyper-V presente",
}

// classifyVM agrega los indicadores encontrados. Función pura para testeo.
func classifyVM(foundPaths []string) VMIndicator {
	var reasons []string
	for _, p := range foundPaths {
		for marker, reason := range vmArtifactMarkers {
			if strings.Contains(p, marker) {
				reasons = append(reasons, reason)
			}
		}
	}
	return VMIndicator{Detected: len(reasons) > 0, Reasons: reasons}
}

// DetectVM inspecciona el sistema real y clasifica los artefactos hallados.
func DetectVM() VMIndicator {
	candidates := []string{
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vboxguest.sys`,
		`C:\Windows\System32\drivers\prl_fs.sys`,
		`C:\Program Files\VMware\VMware Tools`,
		`C:\Program Files\Oracle\VirtualBox Guest Additions`,
	}
	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
		}
	}
	return classifyVM(found)
}
