package privilege

import "testing"

func TestClassifyVMFromArtifactsPositive(t *testing.T) {
	artifacts := []string{
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Program Files\VMware\VMware Tools\`,
	}
	got := classifyVM(artifacts)
	if !got.Detected {
		t.Fatal("esperaba Detected=true con artefactos de VMware")
	}
	if len(got.Reasons) != 2 {
		t.Fatalf("len(Reasons) = %d, want 2", len(got.Reasons))
	}
}

func TestClassifyVMFromArtifactsNegative(t *testing.T) {
	got := classifyVM([]string{`C:\Windows\System32\drivers\disk.sys`})
	if got.Detected {
		t.Fatalf("esperaba Detected=false, got Reasons=%v", got.Reasons)
	}
}
