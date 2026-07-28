package vss

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrUnsupported se devuelve al intentar crear un snapshot fuera de Windows.
var ErrUnsupported = errors.New("VSS solo disponible en Windows")

// Snapshot representa un shadow copy montado y accesible por path.
type Snapshot interface {
	DeviceObjectPath() string
	Close() error
}

var shadowIDRe = regexp.MustCompile(`ShadowID\s*=\s*"(\{[0-9A-Fa-f-]+\})"`)

// parseShadowID extrae el GUID del shadow copy del output de
// `wmic shadowcopy call create`.
func parseShadowID(wmicOutput string) (string, error) {
	m := shadowIDRe.FindStringSubmatch(wmicOutput)
	if len(m) < 2 {
		return "", fmt.Errorf("ShadowID no encontrado en el output de wmic")
	}
	return m[1], nil
}

// PathIn compone un path dentro del snapshot montado.
func PathIn(s Snapshot, relative string) string {
	return s.DeviceObjectPath() + `\` + relative
}
