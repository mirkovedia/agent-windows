package report

import (
	"encoding/json"
	"testing"
)

func TestVerdictLevelsAreDistinct(t *testing.T) {
	levels := map[string]bool{
		LevelLimpio:          true,
		LevelSospechoso:      true,
		LevelEvidenciaFuerte: true,
		LevelIncompleto:      true,
	}
	if len(levels) != 4 {
		t.Fatalf("los cuatro niveles deben ser distintos, obtuve %d", len(levels))
	}
}

func TestReportCarriesVerdictInJSON(t *testing.T) {
	r := Report{
		SessionID: "s1",
		Verdict: Verdict{
			Level:            LevelIncompleto,
			Summary:          "escaneo degradado",
			Reasons:          []string{"colector mft falló"},
			FailedCollectors: []string{"mft_timestomp"},
		},
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Verdict.Level != LevelIncompleto {
		t.Fatalf("Level = %q, want %q", got.Verdict.Level, LevelIncompleto)
	}
	if len(got.Verdict.FailedCollectors) != 1 || got.Verdict.FailedCollectors[0] != "mft_timestomp" {
		t.Fatalf("FailedCollectors = %+v", got.Verdict.FailedCollectors)
	}
	if got.Verdict.Summary != "escaneo degradado" {
		t.Fatalf("Summary = %q", got.Verdict.Summary)
	}
}
