// internal/winfs/services/services_test.go
package services

import (
	"encoding/binary"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/reghive/reghivetest"
)

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func utf16(s string) []byte {
	b := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func buildServicesHive(t *testing.T) *reghive.Hive {
	t.Helper()
	b := reghivetest.NewBuilder()

	// Servicio 1: driver kernel legítimo en System32\drivers.
	v1Type := b.AddValue("Type", u32(1), 4)
	v1Path := b.AddValue("ImagePath", utf16(`\SystemRoot\System32\drivers\afd.sys`), 2)
	svc1 := b.AddKey("Afd", nil, []uint32{v1Type, v1Path})

	// Servicio 2: driver kernel sospechoso, fuera de System32\drivers.
	v2Type := b.AddValue("Type", u32(1), 4)
	v2Path := b.AddValue("ImagePath", utf16(`C:\Users\Player\AppData\Local\Temp\evil.sys`), 2)
	svc2 := b.AddKey("EvilDrv", nil, []uint32{v2Type, v2Path})

	// Servicio 3: Win32 normal (no driver); no debe pasar el filtro aunque el path sea raro.
	v3Type := b.AddValue("Type", u32(0x10), 4)
	v3Path := b.AddValue("ImagePath", utf16(`C:\Temp\raro.exe`), 2)
	svc3 := b.AddKey("RandomSvc", nil, []uint32{v3Type, v3Path})

	// Servicio 4: malformado, sin Type. Debe omitirse sin abortar el resto.
	v4Path := b.AddValue("ImagePath", utf16(`C:\Temp\sin-type.sys`), 2)
	svc4 := b.AddKey("NoType", nil, []uint32{v4Path})

	servicesKey := b.AddKey("Services", []uint32{svc1, svc2, svc3, svc4}, nil)
	data := b.Build(servicesKey)

	h, err := reghive.Open(data)
	if err != nil {
		t.Fatalf("reghive.Open: %v", err)
	}
	return h
}

func TestParseServices(t *testing.T) {
	h := buildServicesHive(t)
	key, err := h.OpenKey("")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	got, err := ParseServices(key)
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	// 4 subclaves; NoType se omite por Type ausente -> 3 servicios válidos.
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3: %+v", len(got), got)
	}
}

func TestIsNonMicrosoftDriver(t *testing.T) {
	cases := []struct {
		name string
		svc  DriverService
		want bool
	}{
		{"kernel driver en System32", DriverService{Type: 1, ImagePath: `\SystemRoot\System32\drivers\afd.sys`}, false},
		{"kernel driver en Temp", DriverService{Type: 1, ImagePath: `C:\Users\Player\AppData\Local\Temp\evil.sys`}, true},
		{"filesystem driver en System32", DriverService{Type: 2, ImagePath: `system32\drivers\netbt.sys`}, false},
		{"Win32 own process fuera de System32", DriverService{Type: 0x10, ImagePath: `C:\Temp\raro.exe`}, false},
		{"prefijo NT device path", DriverService{Type: 1, ImagePath: `\??\C:\Temp\evil.sys`}, true},
	}
	for _, c := range cases {
		if got := IsNonMicrosoftDriver(c.svc); got != c.want {
			t.Errorf("%s: IsNonMicrosoftDriver = %v, want %v", c.name, got, c.want)
		}
	}
}
