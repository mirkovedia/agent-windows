package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/telagem/agent-windows/internal/report"
)

// LocalUploader implementa Uploader sin red: abre una sesión local y escribe el
// reporte final a disco. Permite correr el agente de forma autónoma (sin
// servidor de verificación) conservando intacta la cadena de custodia: el
// nonce sigue siendo aleatorio por sesión y la firma se guarda en el archivo.
//
// El reporte resultante NO está verificado por un tercero: sirve para
// inspección local, no como evidencia con cadena de custodia remota.
type LocalUploader struct {
	path string
}

// NewLocalUploader crea un uploader que vuelca el reporte en path.
func NewLocalUploader(path string) *LocalUploader {
	return &LocalUploader{path: path}
}

// OpenSession genera identificadores locales sin contactar a ningún servidor.
func (u *LocalUploader) OpenSession(ctx context.Context, req OpenRequest) (Session, error) {
	id, err := randomHex(8)
	if err != nil {
		return Session{}, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return Session{}, err
	}
	return Session{SessionID: "local-" + id, Nonce: nonce}, nil
}

// StreamFinding es un no-op: en modo local los findings se persisten juntos al
// completar, no en streaming.
func (u *LocalUploader) StreamFinding(ctx context.Context, sessionID string, seq int, f report.Finding, chainHash string) error {
	return nil
}

// Heartbeat es un no-op: no hay servidor al que reportar progreso.
func (u *LocalUploader) Heartbeat(ctx context.Context, sessionID string, seq int) error {
	return nil
}

// Complete escribe el reporte final como JSON legible y devuelve la ruta del
// archivo (en vez de una URL de verificación remota).
func (u *LocalUploader) Complete(ctx context.Context, sessionID string, r report.Report, sigHex, root string) (string, error) {
	r.Signature = sigHex
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(u.path, data, 0o600); err != nil {
		return "", fmt.Errorf("no se pudo escribir el reporte en %s: %w", u.path, err)
	}
	return u.path, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
