package verdict

import (
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
)

func TestTimeOfMFTTimestomp(t *testing.T) {
	want := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	a := art("mft_timestomp", `C:\x.exe`, map[string]any{
		"SI": map[string]any{"Created": want},
	})
	got, ok := timeOf(a)
	if !ok {
		t.Fatal("mft_timestomp debería exponer tiempo vía SI.Created")
	}
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTimeOfDeletedEntry(t *testing.T) {
	want := time.Date(2026, 7, 30, 11, 0, 0, 0, time.UTC)
	a := art("deleted_entry", `C:\y.exe`, map[string]any{
		"SI": map[string]any{"Created": want},
	})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfUSN(t *testing.T) {
	want := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	a := art("usn", `C:\z.exe`, map[string]any{"Timestamp": want})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfEventlogUsesLowercaseTag(t *testing.T) {
	want := time.Date(2026, 7, 30, 13, 0, 0, 0, time.UTC)
	a := art("eventlog.log_cleared", "Security", map[string]any{"time": want})
	if got, ok := timeOf(a); !ok || !got.Equal(want) {
		t.Fatalf("got %v ok=%v, want %v", got, ok, want)
	}
}

func TestTimeOfTypesWithoutTime(t *testing.T) {
	for _, tp := range []string{"service_driver", "scheduled_task", "scheduled_task_desync", "eventlog.desync", "eventlog.tamper_signal"} {
		a := art(tp, "X", map[string]any{"Name": "algo"})
		if _, ok := timeOf(a); ok {
			t.Errorf("%s no debería exponer tiempo", tp)
		}
	}
}

func TestTimeOfCorruptDataIsNotFatal(t *testing.T) {
	a := collector.Artifact{Type: "usn", Source: "X", Data: []byte("{roto")}
	if _, ok := timeOf(a); ok {
		t.Fatal("un payload ilegible no puede reportar tiempo válido")
	}
}

func ev(artType, category, severity string, conf float64, at time.Time, hasTime bool) evaluated {
	return evaluated{
		finding: report.Finding{
			ID: artType, Category: category, Severity: severity,
			Confidence: conf, Title: "t-" + artType,
		},
		artType: artType,
		at:      at,
		hasTime: hasTime,
	}
}

func maxSeverity(items []evaluated) string {
	best := SevInfo
	for _, it := range items {
		if severityRank(it.finding.Severity) > severityRank(best) {
			best = it.finding.Severity
		}
	}
	return best
}

func TestComboAntiForensicClusterRaisesToCritical(t *testing.T) {
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, time.Time{}, false),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if maxSeverity(got) != SevCritical {
		t.Fatalf("dos señales anti-forenses distintas deben producir CRITICAL, got %s", maxSeverity(got))
	}
}

func TestComboSameTypeRepeatedDoesNotCluster(t *testing.T) {
	items := []evaluated{
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if maxSeverity(got) == SevCritical {
		t.Fatal("el mismo tipo repetido no es un cluster: no debe escalar a CRITICAL")
	}
}

func TestComboPersistenceWithClearedLogs(t *testing.T) {
	items := []evaluated{
		ev("service_driver", CatPersistence, SevMedium, 0.5, time.Time{}, false),
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, time.Time{}, false),
	}
	got := applyCombos(items)
	var persistence evaluated
	for _, it := range got {
		if it.artType == "service_driver" {
			persistence = it
		}
	}
	if persistence.finding.Severity != SevCritical {
		t.Fatalf("persistencia + logs borrados debe ser CRITICAL, got %s", persistence.finding.Severity)
	}
}

func TestComboTemporalAmplifierWithinWindow(t *testing.T) {
	base := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, base, true),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, base.Add(10*time.Minute), true),
	}
	got := applyCombos(items)
	var maxConf float64
	for _, it := range got {
		if it.finding.Confidence > maxConf {
			maxConf = it.finding.Confidence
		}
	}
	if maxConf <= 0.9 {
		t.Fatalf("señales dentro de la ventana deben amplificar la confianza, got %v", maxConf)
	}
	if maxConf > 1.0 {
		t.Fatalf("la confianza no puede pasar de 1.0, got %v", maxConf)
	}
}

func TestComboNoAmplifierOutsideWindow(t *testing.T) {
	base := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	items := []evaluated{
		ev("eventlog.log_cleared", CatAntiForensic, SevHigh, 0.9, base, true),
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, base.Add(5*time.Hour), true),
	}
	got := applyCombos(items)
	for _, it := range got {
		if it.finding.Confidence > 0.9 {
			t.Fatalf("fuera de la ventana no debe amplificarse, got %v", it.finding.Confidence)
		}
	}
}

func TestComboSingleSignalUnchanged(t *testing.T) {
	items := []evaluated{
		ev("mft_timestomp", CatAntiForensic, SevHigh, 0.8, time.Time{}, false),
	}
	got := applyCombos(items)
	if got[0].finding.Severity != SevHigh {
		t.Fatalf("una sola señal no escala, got %s", got[0].finding.Severity)
	}
}
