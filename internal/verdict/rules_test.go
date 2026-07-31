package verdict

import "testing"

func TestRuleForStrongSignals(t *testing.T) {
	cases := []struct {
		artifactType string
		category     string
		severity     string
	}{
		{"eventlog.log_cleared", CatAntiForensic, SevHigh},
		{"mft_timestomp", CatAntiForensic, SevHigh},
		{"eventlog.tamper_signal", CatAntiForensic, SevHigh},
		{"eventlog.desync", CatAntiForensic, SevMedium},
		{"scheduled_task_desync", CatAntiForensic, SevMedium},
		{"service_driver", CatPersistence, SevMedium},
		{"scheduled_task", CatPersistence, SevMedium},
		{"deleted_entry", CatAntiForensic, SevLow},
	}
	for _, c := range cases {
		r := ruleFor(c.artifactType)
		if r.Category != c.category || r.Severity != c.severity {
			t.Errorf("%s: got %s/%s, want %s/%s", c.artifactType, r.Category, r.Severity, c.category, c.severity)
		}
		if r.Confidence <= 0 {
			t.Errorf("%s: una señal fuerte debe tener confianza > 0", c.artifactType)
		}
	}
}

func TestNeutralTypesAreInfo(t *testing.T) {
	for _, tp := range []string{"prefetch", "bam", "shimcache", "amcache", "usn", "eventlog.session_timeline"} {
		r := ruleFor(tp)
		if r.Severity != SevInfo || r.Category != CatExecution {
			t.Errorf("%s: got %s/%s, want %s/%s", tp, r.Category, r.Severity, CatExecution, SevInfo)
		}
		if !isNeutral(tp) {
			t.Errorf("%s debería ser neutro", tp)
		}
	}
}

func TestUnknownTypeIsNeutral(t *testing.T) {
	r := ruleFor("colector_del_futuro")
	if r.Severity != SevInfo || r.Category != CatExecution {
		t.Fatalf("tipo desconocido debe caer en neutro, got %s/%s", r.Category, r.Severity)
	}
	if !isNeutral("colector_del_futuro") {
		t.Fatal("tipo desconocido debe contarse como neutro")
	}
}

func TestStrongTypesAreNotNeutral(t *testing.T) {
	if isNeutral("mft_timestomp") {
		t.Fatal("mft_timestomp no es evidencia neutra")
	}
}

func TestSeverityRankOrder(t *testing.T) {
	if !(severityRank(SevInfo) < severityRank(SevLow) &&
		severityRank(SevLow) < severityRank(SevMedium) &&
		severityRank(SevMedium) < severityRank(SevHigh) &&
		severityRank(SevHigh) < severityRank(SevCritical)) {
		t.Fatal("el orden de severidad es incorrecto")
	}
}

func TestBumpSeveritySaturates(t *testing.T) {
	if got := bumpSeverity(SevLow, 2); got != SevHigh {
		t.Errorf("LOW+2 = %s, want HIGH", got)
	}
	if got := bumpSeverity(SevInfo, 2); got != SevMedium {
		t.Errorf("INFO+2 = %s, want MEDIUM", got)
	}
	if got := bumpSeverity(SevHigh, 2); got != SevCritical {
		t.Errorf("HIGH+2 debe saturar en CRITICAL, got %s", got)
	}
	if got := bumpSeverity(SevCritical, 1); got != SevCritical {
		t.Errorf("CRITICAL no puede subir más, got %s", got)
	}
}
