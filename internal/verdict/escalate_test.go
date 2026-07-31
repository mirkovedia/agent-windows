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

func TestEscalateCorruptDataKeepsBase(t *testing.T) {
	a := collector.Artifact{Type: "scheduled_task_desync", Source: "X", Data: []byte("{no es json")}
	base := ruleFor("scheduled_task_desync")
	got := escalate(a, base)
	if got.Severity != base.Severity {
		t.Fatalf("Data corrupta debe dejar la regla base, got %s want %s", got.Severity, base.Severity)
	}
}
