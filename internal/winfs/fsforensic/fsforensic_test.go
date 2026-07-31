package fsforensic

import (
	"reflect"
	"testing"
)

func TestHasForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"cheat.exe":      true,
		"driver.SYS":     true,
		"script.ps1":     true,
		"documento.docx": false,
		"foto.jpg":       false,
		"sinextension":   false,
	}
	for name, want := range cases {
		if got := HasForensicExtension(name); got != want {
			t.Errorf("HasForensicExtension(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"logUploaderSettings.ini", []string{"log", "uploader", "settings", "ini"}},
		{"FreeFire_Injector.exe", []string{"free", "fire", "injector", "exe"}},
		{"pyproject-hooks.rkyv", []string{"pyproject", "hooks", "rkyv"}},
		{"esp.dll", []string{"esp", "dll"}},
		// Los llamadores pasan la ruta completa, no solo el nombre: hay que
		// cortar tambien por separadores de ruta.
		{`C:\Windows\Prefetch\INJECTOR.EXE-1234.pf`,
			[]string{"c", "windows", "prefetch", "injector", "exe", "1234", "pf"}},
	}
	for _, c := range cases {
		if got := tokenize(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tokenize(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestIsSuspiciousNameRealFalsePositives usa los nombres exactos que la
// primera ejecución real (2026-07-31) clasificó mal sobre una máquina limpia.
func TestIsSuspiciousNameRealFalsePositives(t *testing.T) {
	limpios := []string{
		// El único CRITICAL del reporte: caché del gestor de paquetes uv.
		"pyproject-hooks.rkyv",
		// Los 767 MEDIUM de USN.
		"logUploaderSettings.ini",
		"logUploaderSettings_temp.ini",
		"gamingservicesproxy_11.dll",
		// Manifiestos WinSxS: los 83 HIGH.
		"amd64_microsoft-windows-k..s-loader-deployment_31bf3856ad364e35_10.0.26100.8972_none_ffe303a9132d3dcd.manifest",
		"amd64_microsoft-windows-i..derninjectionbroker_31bf3856ad364e35_10.0.26100.8972_none_dbaeabf8478efa20.manifest",
		"amd64_microsoft-onecore-m..lnamespaceextension_31bf3856ad364e35_10.0.26100.8972_none_691608c8ce3ff087.manifest",
		"amd64_microsoft-windows-c..ore-earlydownloader_31bf3856ad364e35_10.0.26100.8972_none_61dae73cb281a585.manifest",
		"amd64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35_10.0.26100.8972_none_6a0e0ddc1e647f95.manifest",
		"amd64_microsoft-onecore-w..hreatresponseengine_31bf3856ad364e35_10.0.26100.8972_none_5af092601200b56e.manifest",
		"amd64_microsoft-windows-s..agespaces-spaceutil_31bf3856ad364e35_10.0.26100.8972_none_77f71f2e7f54f72f.manifest",
		// Nombres normales.
		"notepad.exe",
		"informe.docx",
	}
	for _, n := range limpios {
		if IsSuspiciousName(n) {
			t.Errorf("IsSuspiciousName(%q) = true, es un archivo legítimo", n)
		}
	}
}

func TestIsSuspiciousNameStillDetects(t *testing.T) {
	sospechosos := []string{
		"FreeFire_Injector.exe", // token "injector"
		"aimbot_loader.exe",     // marcador fuerte "aimbot"
		"aimbotloader.exe",      // fuerte, sin separadores
		"esp.dll",               // token exacto "esp"
		"cheat.exe",             // fuerte
		"CCleaner.exe",          // fuerte
		"hook.dll",              // token exacto "hook"
		"macro_v2.ahk",          // token exacto "macro"
	}
	for _, n := range sospechosos {
		if !IsSuspiciousName(n) {
			t.Errorf("IsSuspiciousName(%q) = false, debería detectarse", n)
		}
	}
}

func TestIsSystemComponent(t *testing.T) {
	componentes := []string{
		"amd64_microsoft-windows-k..s-loader-deployment_31bf3856ad364e35_10.0.26100.8972_none_ffe303a9132d3dcd.manifest",
		"wow64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35_10.0.26100.8972_none_7462b82e52c54190.manifest",
	}
	for _, n := range componentes {
		if !IsSystemComponent(n) {
			t.Errorf("IsSystemComponent(%q) = false, es un componente WinSxS", n)
		}
	}
	normales := []string{"notepad.exe", "aimbot.exe", "microsoft-word.docx"}
	for _, n := range normales {
		if IsSystemComponent(n) {
			t.Errorf("IsSystemComponent(%q) = true, no es un componente WinSxS", n)
		}
	}
}
