// internal/agent/agent.go
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
	"github.com/telagem/agent-windows/internal/verdict"
)

// Options configura una ejecución del agente.
type Options struct {
	Timeout   time.Duration
	ServerURL string
	Version   string
	Machine   report.MachineInfo // estado de la máquina (elevación, VM, OS, uptime)
	// Observer, si tiene callbacks, recibe el avance del escaneo. El modo
	// consola lo deja vacío y se comporta exactamente como antes.
	Observer collector.Observer
}

// runWithCollectors ejecuta el flujo completo con colectores y consentimiento
// inyectados (para testeo). El flag consent simula la aceptación del jugador.
func runWithCollectors(ctx context.Context, opts Options, up transport.Uploader, collectors []collector.Collector, consent bool) (report.Report, error) {
	consentAt := time.Now()
	if !consent {
		return report.Report{}, fmt.Errorf("el jugador no otorgó consentimiento; escaneo abortado")
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return report.Report{}, err
	}

	sess, err := up.OpenSession(ctx, transport.OpenRequest{
		AgentVersion:    opts.Version,
		Pubkey:          hex.EncodeToString(pub),
		ConsentAt:       consentAt,
		MachineInfoHash: "", // se completa en la integración real
	})
	if err != nil {
		return report.Report{}, fmt.Errorf("no se pudo abrir sesión: %w", err)
	}

	chain := report.NewChain(sess.Nonce)
	rep := report.Report{
		SessionID:    sess.SessionID,
		Platform:     "windows",
		AgentVersion: opts.Version,
		StartedAt:    time.Now(),
		ConsentAt:    consentAt,
		Machine:      opts.Machine,
		Status:       "COMPLETE",
	}

	results := collector.RunObserved(ctx, collectors, opts.Observer)
	findings, v := verdict.Evaluate(results)
	rep.Verdict = v
	seq := 0
	for _, f := range findings {
		chainHash, err := chain.Append(f)
		if err != nil {
			continue
		}
		rep.Findings = append(rep.Findings, f)
		_ = up.StreamFinding(ctx, sess.SessionID, seq, f, chainHash)
		seq++
	}

	rep.HashChain = chain.Hashes()
	rep.EndedAt = time.Now()
	root := chain.Root()
	rep.Signature = report.Sign(priv, root)

	if _, err := up.Complete(ctx, sess.SessionID, rep, rep.Signature, root); err != nil {
		return rep, fmt.Errorf("no se pudo completar la sesión: %w", err)
	}
	return rep, nil
}

