package report

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func fixedFinding(id string) Finding {
	ts := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	return Finding{
		ID: id, Category: "EXECUTION", Severity: "HIGH", Confidence: 0.9,
		Title: "t", Evidence: "e", Artifact: "prefetch", Timestamp: &ts,
	}
}

func TestChainIsDeterministic(t *testing.T) {
	c1 := NewChain("nonce-abc")
	h1a, _ := c1.Append(fixedFinding("a"))
	h1b, _ := c1.Append(fixedFinding("b"))

	c2 := NewChain("nonce-abc")
	h2a, _ := c2.Append(fixedFinding("a"))
	h2b, _ := c2.Append(fixedFinding("b"))

	if h1a != h2a || h1b != h2b {
		t.Fatalf("cadena no determinista: (%s,%s) vs (%s,%s)", h1a, h1b, h2a, h2b)
	}
}

func TestChainDependsOnNonce(t *testing.T) {
	c1 := NewChain("nonce-1")
	h1, _ := c1.Append(fixedFinding("a"))
	c2 := NewChain("nonce-2")
	h2, _ := c2.Append(fixedFinding("a"))
	if h1 == h2 {
		t.Fatal("un nonce distinto debe producir una cadena distinta")
	}
}

func TestTamperBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := NewChain("nonce")
	c.Append(fixedFinding("a"))
	c.Append(fixedFinding("b"))
	root := c.Root()
	sig := Sign(priv, root)

	if !Verify(pub, root, sig) {
		t.Fatal("la firma válida debería verificar")
	}
	// Alterar un finding cambia el root → la firma vieja no verifica.
	c.Append(fixedFinding("c"))
	if Verify(pub, c.Root(), sig) {
		t.Fatal("la firma vieja no debería verificar contra un root alterado")
	}
}
