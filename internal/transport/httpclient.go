package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/telagem/agent-windows/internal/report"
)

const maxRetries = 3

// HTTPUploader implementa Uploader contra el contrato HTTP+JSON.
type HTTPUploader struct {
	baseURL      string
	hc           *http.Client
	retryBackoff time.Duration
}

// NewHTTPUploader construye un uploader con backoff exponencial base 200ms.
func NewHTTPUploader(baseURL string, hc *http.Client) *HTTPUploader {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPUploader{baseURL: baseURL, hc: hc, retryBackoff: 200 * time.Millisecond}
}

// doJSON hace un POST JSON con reintentos y backoff exponencial. Devuelve el
// body de respuesta decodificado en out (si out != nil).
func (u *HTTPUploader) doJSON(ctx context.Context, path string, body, out any, okStatus ...int) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	backoff := u.retryBackoff
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := u.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if !statusOK(resp.StatusCode, okStatus) {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", path, resp.StatusCode)
			continue
		}
		defer resp.Body.Close()
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	return fmt.Errorf("agotados %d reintentos: %w", maxRetries, lastErr)
}

func statusOK(code int, want []int) bool {
	if len(want) == 0 {
		return code >= 200 && code < 300
	}
	for _, w := range want {
		if code == w {
			return true
		}
	}
	return false
}

func (u *HTTPUploader) OpenSession(ctx context.Context, req OpenRequest) (Session, error) {
	var s Session
	err := u.doJSON(ctx, "/api/v1/sessions", req, &s)
	return s, err
}

func (u *HTTPUploader) StreamFinding(ctx context.Context, sessionID string, seq int, f report.Finding, chainHash string) error {
	body := map[string]any{"seq": seq, "finding": f, "chainHash": chainHash}
	return u.doJSON(ctx, "/api/v1/sessions/"+sessionID+"/findings", body, nil, http.StatusAccepted, http.StatusOK)
}

func (u *HTTPUploader) Complete(ctx context.Context, sessionID string, r report.Report, sigHex, root string) (string, error) {
	body := map[string]any{"report": r, "signature": sigHex, "hashRoot": root}
	var out struct {
		VerifyURL string `json:"verifyUrl"`
	}
	err := u.doJSON(ctx, "/api/v1/sessions/"+sessionID+"/complete", body, &out)
	return out.VerifyURL, err
}

func (u *HTTPUploader) Heartbeat(ctx context.Context, sessionID string, seq int) error {
	return u.doJSON(ctx, "/api/v1/sessions/"+sessionID+"/heartbeat", map[string]int{"seq": seq}, nil)
}
