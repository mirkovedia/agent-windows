package transport

import (
	"context"
	"time"

	"github.com/telagem/agent-windows/internal/report"
)

// Session identifica una sesión abierta en el servidor.
type Session struct {
	SessionID string `json:"sessionId"`
	Nonce     string `json:"nonce"`
}

// OpenRequest es el body para abrir una sesión.
type OpenRequest struct {
	AgentVersion    string    `json:"agentVersion"`
	Pubkey          string    `json:"pubkey"`
	ConsentAt       time.Time `json:"consentAt"`
	MachineInfoHash string    `json:"machineInfoHash"`
}

// Uploader sube la sesión y sus hallazgos al servidor de verificación.
type Uploader interface {
	OpenSession(ctx context.Context, req OpenRequest) (Session, error)
	StreamFinding(ctx context.Context, sessionID string, seq int, f report.Finding, chainHash string) error
	Complete(ctx context.Context, sessionID string, r report.Report, sigHex, root string) (string, error)
	Heartbeat(ctx context.Context, sessionID string, seq int) error
}
