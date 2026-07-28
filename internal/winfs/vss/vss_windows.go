//go:build windows

package vss

import (
	"fmt"
	"os/exec"
	"strings"
)

type wmicSnapshot struct {
	shadowID   string
	devicePath string
}

func (s *wmicSnapshot) DeviceObjectPath() string { return s.devicePath }

func (s *wmicSnapshot) Close() error {
	return exec.Command("vssadmin", "delete", "shadows", "/Shadow="+s.shadowID, "/quiet").Run()
}

// Create crea un shadow copy del volumen (ej. "C:\\") vía WMI.
func Create(volume string) (Snapshot, error) {
	out, err := exec.Command("wmic", "shadowcopy", "call", "create",
		"Volume="+volume).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wmic shadowcopy create falló: %w", err)
	}
	id, err := parseShadowID(string(out))
	if err != nil {
		return nil, err
	}
	device, err := resolveDevicePath(id)
	if err != nil {
		return nil, err
	}
	return &wmicSnapshot{shadowID: id, devicePath: device}, nil
}

// resolveDevicePath obtiene el DeviceObject del shadow copy vía vssadmin.
func resolveDevicePath(shadowID string) (string, error) {
	out, err := exec.Command("vssadmin", "list", "shadows", "/Shadow="+shadowID).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("vssadmin list shadows falló: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, `\\?\GLOBALROOT`); idx >= 0 {
			return strings.TrimSpace(line[idx:]), nil
		}
	}
	return "", fmt.Errorf("DeviceObject no encontrado para %s", shadowID)
}
