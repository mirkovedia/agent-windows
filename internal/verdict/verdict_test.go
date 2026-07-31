package verdict

import (
	"errors"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
)

func resultWith(name string, arts ...collector.Artifact) collector.Result {
	return collector.Result{Collector: name, Artifacts: arts}
}

func TestEvaluateCollapsesNeutralEvidence(t *testing.T) {
	var arts []collector.Artifact
	for i := 0; i < 100; i++ {
		arts = append(arts, art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil))
	}
	findings, _ := Evaluate([]collector.Result{resultWith("prefetch", arts...)})
	if len(findings) != 1 {
		t.Fatalf("100 artefactos neutros deben colapsar en 1 resumen, got %d", len(findings))
	}
	if findings[0].Severity != SevInfo {
		t.Fatalf("el resumen debe ser INFO, got %s", findings[0].Severity)
	}
}

func TestEvaluateEmitsSuspiciousNeutralIndividually(t *testing.T) {
	arts := []collector.Artifact{
		art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil),
		art("prefetch", `C:\Windows\Prefetch\INJECTOR.EXE-2.pf`, nil),
	}
	findings, _ := Evaluate([]collector.Result{resultWith("prefetch", arts...)})
	// 1 resumen + 1 individual escalado
	if len(findings) != 2 {
		t.Fatalf("esperaba resumen + 1 individual, got %d: %+v", len(findings), findings)
	}
	var sawMedium bool
	for _, f := range findings {
		if f.Severity == SevMedium {
			sawMedium = true
		}
	}
	if !sawMedium {
		t.Fatal("el prefetch sospechoso debe emitirse como MEDIUM")
	}
}

func TestEvaluateStrongSignalIsNotCollapsed(t *testing.T) {
	findings, _ := Evaluate([]collector.Result{
		resultWith("mft", art("mft_timestomp", `C:\x.exe`, nil)),
	})
	if len(findings) != 1 || findings[0].Severity != SevHigh {
		t.Fatalf("una señal fuerte se emite tal cual, got %+v", findings)
	}
}

func TestEvaluateFailedCollectorProducesFindingAndVerdict(t *testing.T) {
	res := collector.Result{Collector: "mft_timestomp", Err: errors.New("acceso denegado")}
	findings, v := Evaluate([]collector.Result{res})
	if len(findings) != 1 {
		t.Fatalf("un colector caído debe emitir un hallazgo, got %d", len(findings))
	}
	if len(v.FailedCollectors) != 1 || v.FailedCollectors[0] != "mft_timestomp" {
		t.Fatalf("FailedCollectors = %+v", v.FailedCollectors)
	}
}

func TestVerdictCleanScanIsLimpio(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("prefetch", art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil)),
	})
	if v.Level != report.LevelLimpio {
		t.Fatalf("Level = %q, want LIMPIO", v.Level)
	}
}

func TestVerdictCleanScanWithFailedCollectorIsIncompleto(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("prefetch", art("prefetch", `C:\Windows\Prefetch\NOTEPAD.EXE-1.pf`, nil)),
		{Collector: "mft_timestomp", Err: errors.New("acceso denegado")},
	})
	if v.Level != report.LevelIncompleto {
		t.Fatalf("un escaneo degradado sin hallazgos no puede ser LIMPIO, got %q", v.Level)
	}
}

func TestVerdictSuspiciousStaysSuspiciousWhenDegraded(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("mft", art("mft_timestomp", `C:\x.exe`, nil)),
		{Collector: "usn", Err: errors.New("acceso denegado")},
	})
	if v.Level != report.LevelSospechoso {
		t.Fatalf("la evidencia hallada no se degrada, got %q", v.Level)
	}
	if len(v.FailedCollectors) != 1 {
		t.Fatal("pero el fallo debe quedar listado para que el lector lo pondere")
	}
}

func TestVerdictCriticalIsEvidenciaFuerte(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("eventlog",
			art("eventlog.log_cleared", "Security", nil),
			art("mft_timestomp", `C:\x.exe`, nil),
		),
	})
	if v.Level != report.LevelEvidenciaFuerte {
		t.Fatalf("un cluster anti-forense es EVIDENCIA_FUERTE, got %q", v.Level)
	}
	if v.Summary == "" {
		t.Fatal("el veredicto necesita un resumen legible")
	}
	if len(v.Reasons) == 0 {
		t.Fatal("el veredicto debe enumerar por qué llegó a ese nivel")
	}
}

func TestVerdictTwoMediumsIsSospechoso(t *testing.T) {
	_, v := Evaluate([]collector.Result{
		resultWith("svc", art("service_driver", `C:\Temp\a.sys`, nil)),
		resultWith("sched", art("eventlog.desync", "Updater", nil)),
	})
	if v.Level != report.LevelSospechoso {
		t.Fatalf("dos MEDIUM son SOSPECHOSO, got %q", v.Level)
	}
}

func TestEvaluateEmptyInput(t *testing.T) {
	findings, v := Evaluate(nil)
	if len(findings) != 0 {
		t.Fatalf("sin resultados no hay hallazgos, got %+v", findings)
	}
	if v.Level != report.LevelLimpio {
		t.Fatalf("sin colectores caídos el nivel es LIMPIO, got %q", v.Level)
	}
}
