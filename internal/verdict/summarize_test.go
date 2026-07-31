package verdict

import (
	"strings"
	"testing"
)

func TestSummaryFindingCountsArtifacts(t *testing.T) {
	f := summaryFinding("prefetch", 1247, 3)
	if f.Severity != SevInfo || f.Category != CatExecution {
		t.Fatalf("el resumen debe ser INFO/EXECUTION, got %s/%s", f.Category, f.Severity)
	}
	if !strings.Contains(f.Evidence, "1247") {
		t.Fatalf("la evidencia debe informar el total, got %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "3") {
		t.Fatalf("la evidencia debe informar cuántos se emitieron aparte, got %q", f.Evidence)
	}
	if !strings.Contains(f.Title, "prefetch") {
		t.Fatalf("el título debe nombrar al colector, got %q", f.Title)
	}
	if f.ID == "" {
		t.Fatal("el resumen necesita ID para la cadena de hash")
	}
}

func TestSummaryFindingWithNoEscalations(t *testing.T) {
	f := summaryFinding("bam", 50, 0)
	if !strings.Contains(f.Evidence, "50") {
		t.Fatalf("Evidence = %q", f.Evidence)
	}
}

func TestSummaryFindingIDsAreDistinctPerCollector(t *testing.T) {
	a := summaryFinding("prefetch", 1, 0)
	b := summaryFinding("bam", 1, 0)
	if a.ID == b.ID {
		t.Fatal("dos colectores no pueden compartir el ID del resumen")
	}
}
