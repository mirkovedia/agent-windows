// internal/winfs/services/services.go
package services

import (
	"encoding/binary"
	"strings"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// DriverService es un servicio del registro con sus metadatos crudos.
type DriverService struct {
	Name      string
	ImagePath string
	Type      uint32 // REG_DWORD: 1=kernel driver, 2=filesystem driver, ...
	Start     uint32 // REG_DWORD: 0=Boot..4=Disabled
}

// Valores de Type relevantes (winnt.h). Cualquier otro valor (Win32
// own/share process, etc.) nunca es un driver.
const (
	serviceKernelDriver     = 0x1
	serviceFileSystemDriver = 0x2
)

// ParseServices recorre las subclaves de la clave "Services"
// (SYSTEM\CurrentControlSet\Services) y decodifica Name/ImagePath/Type/Start
// de cada una. Una subclave con Type o ImagePath faltante o malformado se
// omite; no aborta el resto.
func ParseServices(servicesKey *reghive.Key) ([]DriverService, error) {
	subs, err := servicesKey.Subkeys()
	if err != nil {
		return nil, err
	}
	var out []DriverService
	for _, s := range subs {
		vals, err := s.Values()
		if err != nil {
			continue
		}
		typeRaw, ok := vals["Type"]
		if !ok || len(typeRaw) < 4 {
			continue
		}
		imagePathRaw, ok := vals["ImagePath"]
		if !ok {
			continue
		}
		svc := DriverService{
			Name:      s.Name(),
			ImagePath: wintext.DecodeUTF16(imagePathRaw),
			Type:      binary.LittleEndian.Uint32(typeRaw[:4]),
		}
		if startRaw, ok := vals["Start"]; ok && len(startRaw) >= 4 {
			svc.Start = binary.LittleEndian.Uint32(startRaw[:4])
		}
		out = append(out, svc)
	}
	return out, nil
}

// IsNonMicrosoftDriver reporta si el servicio es driver (Type kernel o
// filesystem) cuyo ImagePath normalizado no cae bajo
// %SystemRoot%\System32\drivers\. Es una heurística por RUTA, no por firma
// de editor: sin CGO ni dependencias externas no hay validación de
// Authenticode offline. Cubre tanto binarios de terceros como maliciosos que
// no siguen la convención de instalación de Windows.
func IsNonMicrosoftDriver(s DriverService) bool {
	if s.Type != serviceKernelDriver && s.Type != serviceFileSystemDriver {
		return false
	}
	return !strings.Contains(normalizeImagePath(s.ImagePath), `\windows\system32\drivers\`)
}

// normalizeImagePath resuelve los alias que Windows permite en ImagePath: el
// prefijo de dispositivo NT (\??\), el alias \SystemRoot\, y las rutas
// relativas sin prefijo (frecuentes en drivers de filesystem integrados,
// p.ej. "system32\drivers\netbt.sys"), implícitamente relativas a
// %SystemRoot%.
func normalizeImagePath(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))
	p = strings.TrimPrefix(p, `\??\`)
	switch {
	case strings.HasPrefix(p, `\systemroot\`):
		p = `c:\windows\` + p[len(`\systemroot\`):]
	case !strings.Contains(p, `:`) && !strings.HasPrefix(p, `\`):
		p = `c:\windows\` + p
	}
	return p
}
