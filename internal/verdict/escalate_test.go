package verdict

import (
	"encoding/json"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func art(artifactType, source string, data any) collector.Artifact {
	b, _ := json.Marshal(data)
	return collector.Artifact{Type: artifactType, Source: source, Data: b}
}

func TestEscalateSuspiciousNameRaisesTwoLevels(t *testing.T) {
	// deleted_entry base es LOW; con nombre sospechoso debe llegar a HIGH.
	a := art("deleted_entry", `C:\Temp\aimbot_loader.exe`, nil)
	got := escalate(a, ruleFor("deleted_entry"))
	if got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH", got.Severity)
	}
	if got.Confidence != 0.8 {
		t.Fatalf("Confidence = %v, want 0.8", got.Confidence)
	}
}

func TestEscalateNeutralSuspiciousBecomesMedium(t *testing.T) {
	// prefetch base es INFO; con nombre sospechoso debe llegar a MEDIUM.
	a := art("prefetch", `C:\Windows\Prefetch\INJECTOR.EXE-1234.pf`, nil)
	got := escalate(a, ruleFor("prefetch"))
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
}

// TestEscalateWeakMarkerCapsAtMedium usa run-hook.cmd, el CRITICAL de la
// segunda ejecución real. Es un script de desarrollo: el token "hook" es
// evidencia débil y no puede llevar un archivo borrado hasta HIGH.
func TestEscalateWeakMarkerCapsAtMedium(t *testing.T) {
	a := art("deleted_entry", `C:\proyecto\run-hook.cmd`, nil)
	got := escalate(a, ruleFor("deleted_entry"))
	if got.Severity != SevMedium {
		t.Fatalf("un marcador débil topa en MEDIUM, got %s", got.Severity)
	}
}

func TestEscalateStrongMarkerStillReachesHigh(t *testing.T) {
	a := art("deleted_entry", `C:\Temp\aimbot_loader.exe`, nil)
	got := escalate(a, ruleFor("deleted_entry"))
	if got.Severity != SevHigh {
		t.Fatalf("un marcador fuerte sí llega a HIGH, got %s", got.Severity)
	}
}

func TestEscalateTamperKindsThatAreNotEvidence(t *testing.T) {
	// Ninguno de estos prueba manipulación: log_unreadable es un log que no
	// existe (TaskScheduler/Operational viene deshabilitado en Windows) y
	// dirty_flag es lo normal en un snapshot de un log vivo.
	for _, kind := range []string{"log_unreadable", "dirty_flag", "full_flag"} {
		a := art("eventlog.tamper_signal", kind, map[string]string{"Kind": kind})
		got := escalate(a, ruleFor("eventlog.tamper_signal"))
		if got.Severity != SevInfo {
			t.Errorf("%s debe ser INFO, got %s", kind, got.Severity)
		}
	}
}

func TestEscalateTamperKindsThatAreEvidence(t *testing.T) {
	// Estos sí son manipulación binaria del archivo.
	for _, kind := range []string{"chunk_crc_invalid", "record_id_gap", "truncated"} {
		a := art("eventlog.tamper_signal", kind, map[string]string{"Kind": kind})
		got := escalate(a, ruleFor("eventlog.tamper_signal"))
		if got.Severity != SevHigh {
			t.Errorf("%s debe seguir en HIGH, got %s", kind, got.Severity)
		}
	}
}

func TestEscalateCapsAtHigh(t *testing.T) {
	// service_driver base es MEDIUM; +2 saturaría en CRITICAL, pero el
	// escalado por contenido tiene tope HIGH (CRITICAL es solo de combos).
	a := art("service_driver", `C:\Temp\cheatdrv.sys`, nil)
	got := escalate(a, ruleFor("service_driver"))
	if got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH (tope del escalado por contenido)", got.Severity)
	}
}

func TestEscalateCleanNameUnchanged(t *testing.T) {
	a := art("deleted_entry", `C:\Users\mirko\Documents\informe.docx`, nil)
	base := ruleFor("deleted_entry")
	got := escalate(a, base)
	if got.Severity != base.Severity || got.Confidence != base.Confidence {
		t.Fatalf("un nombre limpio no debe escalar: got %+v, base %+v", got, base)
	}
}

func TestEscalateDesyncHiveOnly(t *testing.T) {
	a := art("scheduled_task_desync", "Updater", map[string]string{"Kind": "hive_only"})
	got := escalate(a, ruleFor("scheduled_task_desync"))
	if got.Severity != SevHigh {
		t.Fatalf("hive_only debe ser HIGH, got %s", got.Severity)
	}
	if got.Confidence != 0.8 {
		t.Fatalf("Confidence = %v, want 0.8", got.Confidence)
	}
}

func TestEscalateDesyncFileOnly(t *testing.T) {
	a := art("scheduled_task_desync", "Updater", map[string]string{"Kind": "file_only"})
	got := escalate(a, ruleFor("scheduled_task_desync"))
	if got.Severity != SevLow {
		t.Fatalf("file_only debe ser LOW, got %s", got.Severity)
	}
}

func TestEscalateTaskNoRegisterLogIsInfo(t *testing.T) {
	// Los Event Logs rotan: una tarea vieja nunca tiene su evento 106, así
	// que la ausencia no prueba nada. Se reporta pero no mueve el veredicto.
	a := art("eventlog.desync", "Updater", map[string]string{"Kind": "task_no_register_log"})
	got := escalate(a, ruleFor("eventlog.desync"))
	if got.Severity != SevInfo {
		t.Fatalf("task_no_register_log debe ser INFO, got %s", got.Severity)
	}
}

func TestEscalateOtherDesyncKindsStayMedium(t *testing.T) {
	for _, kind := range []string{"service_no_install_log", "service_installed_then_removed", "task_delete_desync"} {
		a := art("eventlog.desync", "X", map[string]string{"Kind": kind})
		got := escalate(a, ruleFor("eventlog.desync"))
		if got.Severity != SevMedium {
			t.Errorf("%s debe seguir en MEDIUM, got %s", kind, got.Severity)
		}
	}
}

func TestEscalateMicrosoftHiddenTaskIsInfo(t *testing.T) {
	a := art("scheduled_task", `Microsoft\Windows\UpdateOrchestrator\Reboot`,
		map[string]any{"RelPath": `Microsoft\Windows\UpdateOrchestrator\Reboot`, "Hidden": true})
	got := escalate(a, ruleFor("scheduled_task"))
	if got.Severity != SevInfo {
		t.Fatalf("una tarea oculta de Microsoft debe ser INFO, got %s", got.Severity)
	}
}

func TestEscalateNonMicrosoftHiddenTaskStaysMedium(t *testing.T) {
	a := art("scheduled_task", `MiTareaRara`,
		map[string]any{"RelPath": `MiTareaRara`, "Hidden": true})
	got := escalate(a, ruleFor("scheduled_task"))
	if got.Severity != SevMedium {
		t.Fatalf("una tarea oculta fuera de Microsoft sigue en MEDIUM, got %s", got.Severity)
	}
}

func TestEscalateDriverInNormalLocationIsInfo(t *testing.T) {
	normales := []string{
		`C:\Program Files\Vendor\driver.sys`,
		`C:\Program Files (x86)\Otro\x.sys`,
		`C:\Windows\System32\DriverStore\FileRepository\algo\y.sys`,
	}
	for _, p := range normales {
		a := art("service_driver", p, map[string]any{"ImagePath": p})
		got := escalate(a, ruleFor("service_driver"))
		if got.Severity != SevInfo {
			t.Errorf("driver en %q debe ser INFO, got %s", p, got.Severity)
		}
	}
}

func TestEscalateDriverInSuspiciousLocationStaysMedium(t *testing.T) {
	raros := []string{
		`C:\Users\X\AppData\Local\Temp\evil.sys`,
		`C:\Users\X\Downloads\d.sys`,
	}
	for _, p := range raros {
		a := art("service_driver", p, map[string]any{"ImagePath": p})
		got := escalate(a, ruleFor("service_driver"))
		if got.Severity != SevMedium {
			t.Errorf("driver en %q debe seguir en MEDIUM, got %s", p, got.Severity)
		}
	}
}

func TestEscalateCorruptDataKeepsBase(t *testing.T) {
	a := collector.Artifact{Type: "scheduled_task_desync", Source: "X", Data: []byte("{no es json")}
	base := ruleFor("scheduled_task_desync")
	got := escalate(a, base)
	if got.Severity != base.Severity {
		t.Fatalf("Data corrupta debe dejar la regla base, got %s want %s", got.Severity, base.Severity)
	}
}
