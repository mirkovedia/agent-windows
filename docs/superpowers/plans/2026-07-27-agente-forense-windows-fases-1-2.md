# Agente Forense Windows (Fases 1-2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir el esqueleto del agente forense (elevación, interfaz de colectores, reporte firmado Ed25519 con cadena de custodia y contrato de subida) y los cuatro colectores de ejecución (Prefetch, BAM, ShimCache, AmCache) sobre primitivas Windows de bajo nivel (VSS, parser regf, descompresión MAM).

**Architecture:** Binario único Go sin CGO. Los colectores implementan una interfaz común y corren ordenados por prioridad, aislados de panics. Las primitivas frágiles (`compression`, `reghive`, `vss`) se construyen y testean antes que los colectores que dependen de ellas. El reporte encadena hallazgos con SHA-256 y los firma con Ed25519; se sube en streaming a un contrato HTTP con fallback local-first.

**Tech Stack:** Go 1.22+, `golang.org/x/sys/windows` (syscalls directos a ntdll/kernel32), `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `net/http`, `net/http/httptest`. Sin dependencias externas en runtime.

## Global Constraints

- Target de compilación: `GOOS=windows GOARCH=amd64`, **sin CGO** (`CGO_ENABLED=0`).
- Go 1.22+ como mínimo.
- Module path: `github.com/telagem/agent-windows`.
- Acceso de bajo nivel solo vía `golang.org/x/sys/windows`; nada de librerías que monten volúmenes.
- Sin dependencias externas en runtime (solo stdlib + `golang.org/x/sys`).
- Un colector que falla **nunca** tumba el escaneo: se traduce a un `Finding` categoría `INFO`.
- Nunca recolectar contenido de archivos personales, credenciales, historial ni mensajes: solo metadatos forenses (nombres, hashes, timestamps, paths).
- IDs de hardware hasheados (SHA-256 con nonce como salt) antes de salir del equipo.
- Código en inglés (identificadores, nombres); comentarios y mensajes de commit en español.
- Convención de commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

---

### Task 1: Scaffold del módulo e interfaz Collector

**Files:**
- Create: `go.mod`
- Create: `internal/collector/collector.go`
- Test: `internal/collector/collector_test.go`

**Interfaces:**
- Consumes: nada (primera tarea).
- Produces:
  - `type Artifact struct { Type string; Source string; Data json.RawMessage; Collected time.Time }`
  - `type Collector interface { Name() string; Collect(ctx context.Context) ([]Artifact, error); Priority() int }`
  - Constantes de prioridad: `PriorityVolatile = 10`, `PriorityDisk = 50`, `PriorityRegistry = 40`.

- [ ] **Step 1: Crear `go.mod`**

```
module github.com/telagem/agent-windows

go 1.22

require golang.org/x/sys v0.20.0
```

Luego correr: `go mod download golang.org/x/sys` (o `go mod tidy` tras la primera compilación).

- [ ] **Step 2: Escribir el test que falla**

```go
// internal/collector/collector_test.go
package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type fakeCollector struct {
	name     string
	priority int
}

func (f fakeCollector) Name() string { return f.name }
func (f fakeCollector) Priority() int { return f.priority }
func (f fakeCollector) Collect(ctx context.Context) ([]Artifact, error) {
	return []Artifact{{
		Type:      "fake",
		Source:    "memory",
		Data:      json.RawMessage(`{"ok":true}`),
		Collected: time.Now(),
	}}, nil
}

func TestCollectorInterfaceSatisfied(t *testing.T) {
	var c Collector = fakeCollector{name: "fake", priority: PriorityVolatile}
	if c.Name() != "fake" {
		t.Fatalf("Name() = %q, want %q", c.Name(), "fake")
	}
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if len(arts) != 1 || arts[0].Type != "fake" {
		t.Fatalf("Collect() = %+v, want 1 artifact of type fake", arts)
	}
}

func TestPriorityConstantsOrdered(t *testing.T) {
	if !(PriorityVolatile < PriorityRegistry && PriorityRegistry < PriorityDisk) {
		t.Fatalf("orden de prioridad inválido: volatile=%d registry=%d disk=%d",
			PriorityVolatile, PriorityRegistry, PriorityDisk)
	}
}
```

- [ ] **Step 3: Correr el test para verificar que falla**

Run: `go test ./internal/collector/`
Expected: FAIL de compilación — `undefined: Collector`, `undefined: Artifact`, `undefined: PriorityVolatile`.

- [ ] **Step 4: Escribir la implementación mínima**

```go
// internal/collector/collector.go
package collector

import (
	"context"
	"encoding/json"
	"time"
)

// Prioridades de ejecución: menor corre antes. Los colectores volátiles
// (procesos, memoria, red) van primero; los de disco después.
const (
	PriorityVolatile = 10
	PriorityRegistry = 40
	PriorityDisk     = 50
)

// Artifact es un dato forense estructurado producido por un Collector.
type Artifact struct {
	Type      string          `json:"type"`
	Source    string          `json:"source"`
	Data      json.RawMessage `json:"data"`
	Collected time.Time       `json:"collected"`
}

// Collector recolecta un tipo de artefacto de forma independiente.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Artifact, error)
	Priority() int
}
```

- [ ] **Step 5: Correr el test para verificar que pasa**

Run: `go test ./internal/collector/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/collector/collector.go internal/collector/collector_test.go
git commit -m "feat: scaffold del módulo e interfaz Collector"
```

---

### Task 2: Runner con orden por prioridad y aislamiento de panics

**Files:**
- Create: `internal/collector/runner.go`
- Test: `internal/collector/runner_test.go`

**Interfaces:**
- Consumes: `Collector`, `Artifact` (Task 1).
- Produces:
  - `type Result struct { Collector string; Artifacts []Artifact; Err error }`
  - `func Run(ctx context.Context, collectors []Collector) []Result` — ordena por `Priority()` ascendente, ejecuta cada colector recuperando panics (un panic se convierte en `Result.Err`), respeta la cancelación de `ctx`.

- [ ] **Step 1: Escribir los tests que fallan**

```go
// internal/collector/runner_test.go
package collector

import (
	"context"
	"errors"
	"testing"
)

type stubCollector struct {
	name     string
	priority int
	panics   bool
	err      error
}

func (s stubCollector) Name() string  { return s.name }
func (s stubCollector) Priority() int { return s.priority }
func (s stubCollector) Collect(ctx context.Context) ([]Artifact, error) {
	if s.panics {
		panic("boom")
	}
	if s.err != nil {
		return nil, s.err
	}
	return []Artifact{{Type: s.name}}, nil
}

func TestRunOrdersByPriority(t *testing.T) {
	cols := []Collector{
		stubCollector{name: "disk", priority: PriorityDisk},
		stubCollector{name: "volatile", priority: PriorityVolatile},
		stubCollector{name: "registry", priority: PriorityRegistry},
	}
	results := Run(context.Background(), cols)
	got := []string{results[0].Collector, results[1].Collector, results[2].Collector}
	want := []string{"volatile", "registry", "disk"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden = %v, want %v", got, want)
		}
	}
}

func TestRunRecoversPanic(t *testing.T) {
	cols := []Collector{stubCollector{name: "bad", priority: PriorityVolatile, panics: true}}
	results := Run(context.Background(), cols)
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("esperaba Err no nil tras panic recuperado")
	}
}

func TestRunPropagatesCollectorError(t *testing.T) {
	sentinel := errors.New("falla de disco")
	cols := []Collector{stubCollector{name: "x", priority: PriorityVolatile, err: sentinel}}
	results := Run(context.Background(), cols)
	if !errors.Is(results[0].Err, sentinel) {
		t.Fatalf("Err = %v, want %v", results[0].Err, sentinel)
	}
}
```

- [ ] **Step 2: Correr los tests para verificar que fallan**

Run: `go test ./internal/collector/ -run TestRun`
Expected: FAIL de compilación — `undefined: Run`, `undefined: Result`.

- [ ] **Step 3: Escribir la implementación**

```go
// internal/collector/runner.go
package collector

import (
	"context"
	"fmt"
	"sort"
)

// Result es el resultado de ejecutar un Collector.
type Result struct {
	Collector string
	Artifacts []Artifact
	Err       error
}

// Run ejecuta los colectores ordenados por prioridad ascendente. Un panic
// dentro de un colector se recupera y se traduce a Result.Err: un colector
// que falla nunca tumba el escaneo.
func Run(ctx context.Context, collectors []Collector) []Result {
	ordered := make([]Collector, len(collectors))
	copy(ordered, collectors)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority() < ordered[j].Priority()
	})

	results := make([]Result, 0, len(ordered))
	for _, c := range ordered {
		results = append(results, runOne(ctx, c))
	}
	return results
}

func runOne(ctx context.Context, c Collector) (res Result) {
	res.Collector = c.Name()
	defer func() {
		if r := recover(); r != nil {
			res.Err = fmt.Errorf("panic en colector %s: %v", c.Name(), r)
		}
	}()
	res.Artifacts, res.Err = c.Collect(ctx)
	return res
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/`
Expected: PASS (todos).

- [ ] **Step 5: Commit**

```bash
git add internal/collector/runner.go internal/collector/runner_test.go
git commit -m "feat: runner de colectores con orden por prioridad y aislamiento de panics"
```

---

### Task 3: Detección de elevación (UAC) y de VM/sandbox

**Files:**
- Create: `internal/privilege/privilege.go`
- Create: `internal/privilege/vm.go`
- Test: `internal/privilege/privilege_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func IsElevated() (bool, error)` — true si el token del proceso está elevado.
  - `type VMIndicator struct { Detected bool; Reasons []string }`
  - `func DetectVM() VMIndicator` — heurística por artefactos (nunca aborta, solo informa).

- [ ] **Step 1: Escribir el test que falla (lógica testeable de VM)**

La detección de elevación real depende del SO; la aislamos y testeamos solo la lógica pura de agregación de indicadores de VM.

```go
// internal/privilege/privilege_test.go
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
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/privilege/`
Expected: FAIL de compilación — `undefined: classifyVM`, `undefined: VMIndicator`.

- [ ] **Step 3: Escribir `vm.go` (lógica pura + recolección de artefactos)**

```go
// internal/privilege/vm.go
package privilege

import (
	"os"
	"strings"
)

// VMIndicator reporta si la máquina parece una VM/sandbox y por qué.
// Nunca provoca un aborto: es solo contexto para el reporte.
type VMIndicator struct {
	Detected bool
	Reasons  []string
}

// vmArtifactMarkers son fragmentos de path que delatan un hipervisor.
var vmArtifactMarkers = map[string]string{
	`vmmouse.sys`:   "driver de VMware presente",
	`vmhgfs.sys`:    "driver de VMware presente",
	`VMware Tools`:  "VMware Tools instalado",
	`vboxguest.sys`: "driver de VirtualBox presente",
	`VBoxService`:   "VirtualBox Guest Additions instalado",
	`prl_fs.sys`:    "driver de Parallels presente",
	`vmicheartbeat`: "servicio de integración Hyper-V presente",
}

// classifyVM agrega los indicadores encontrados. Función pura para testeo.
func classifyVM(foundPaths []string) VMIndicator {
	var reasons []string
	for _, p := range foundPaths {
		for marker, reason := range vmArtifactMarkers {
			if strings.Contains(p, marker) {
				reasons = append(reasons, reason)
			}
		}
	}
	return VMIndicator{Detected: len(reasons) > 0, Reasons: reasons}
}

// DetectVM inspecciona el sistema real y clasifica los artefactos hallados.
func DetectVM() VMIndicator {
	candidates := []string{
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vboxguest.sys`,
		`C:\Windows\System32\drivers\prl_fs.sys`,
		`C:\Program Files\VMware\VMware Tools`,
		`C:\Program Files\Oracle\VirtualBox Guest Additions`,
	}
	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
		}
	}
	return classifyVM(found)
}
```

- [ ] **Step 4: Escribir `privilege.go` (elevación vía token del proceso)**

```go
// internal/privilege/privilege.go
package privilege

import "golang.org/x/sys/windows"

// IsElevated reporta si el proceso actual corre con token elevado (UAC).
func IsElevated() (bool, error) {
	var token windows.Token
	proc := windows.CurrentProcess()
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/privilege/`
Expected: PASS. (Nota: `privilege.go` usa build implícito de Windows; en un host no-Windows compilar con `GOOS=windows go build ./internal/privilege/` para verificar. Los tests de `classifyVM` son cross-platform.)

- [ ] **Step 6: Commit**

```bash
git add internal/privilege/
git commit -m "feat: detección de elevación UAC y de VM/sandbox"
```

---

### Task 4: Reporte, cadena de custodia y firma Ed25519

**Files:**
- Create: `internal/report/report.go`
- Create: `internal/report/chain.go`
- Test: `internal/report/chain_test.go`

**Interfaces:**
- Consumes: nada (usa solo stdlib).
- Produces:
  - `type MachineInfo struct { OS, Build string; UptimeMinutes int; Elevated bool; VM bool; VMReasons []string }`
  - `type Finding struct { ID, Category, Severity string; Confidence float64; Title, Evidence, Artifact string; Timestamp *time.Time }`
  - `type Report struct { SessionID, Platform, AgentVersion string; StartedAt, EndedAt, ConsentAt time.Time; Machine MachineInfo; Findings []Finding; HashChain []string; Signature string; Status string }`
  - `type Chain struct { ... }`
  - `func NewChain(nonce string) *Chain` — inicializa con `H_0 = SHA256(nonce)`.
  - `func (c *Chain) Append(f Finding) (chainHash string, err error)` — encadena y devuelve el nuevo hash hex.
  - `func (c *Chain) Root() string` — último hash de la cadena.
  - `func canonicalFindingBytes(f Finding) ([]byte, error)` — JSON canónico (claves ordenadas) del finding.
  - `func Sign(priv ed25519.PrivateKey, root string) string` — firma hex del root.
  - `func Verify(pub ed25519.PublicKey, root, sigHex string) bool`.

- [ ] **Step 1: Escribir los tests que fallan**

```go
// internal/report/chain_test.go
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
```

- [ ] **Step 2: Correr los tests para verificar que fallan**

Run: `go test ./internal/report/`
Expected: FAIL de compilación — `undefined: NewChain`, `undefined: Finding`, etc.

- [ ] **Step 3: Escribir `report.go` (structs)**

```go
// internal/report/report.go
package report

import "time"

// MachineInfo describe el estado de la máquina examinada.
type MachineInfo struct {
	OS            string   `json:"os"`
	Build         string   `json:"build"`
	UptimeMinutes int      `json:"uptimeMinutes"`
	Elevated      bool     `json:"elevated"`
	VM            bool     `json:"vm"`
	VMReasons     []string `json:"vmReasons,omitempty"`
}

// Finding es un hallazgo forense individual.
type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"` // ANTI_FORENSIC | EXECUTION | PERSISTENCE | EMULATOR | KNOWN_CHEAT
	Severity   string     `json:"severity"` // INFO | LOW | MEDIUM | HIGH | CRITICAL
	Confidence float64    `json:"confidence"`
	Title      string     `json:"title"`
	Evidence   string     `json:"evidence"`
	Artifact   string     `json:"artifact"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

// Report es el reporte firmado con cadena de custodia.
type Report struct {
	SessionID    string      `json:"sessionId"`
	Platform     string      `json:"platform"` // "windows"
	AgentVersion string      `json:"agentVersion"`
	StartedAt    time.Time   `json:"startedAt"`
	EndedAt      time.Time   `json:"endedAt"`
	ConsentAt    time.Time   `json:"consentAt"`
	Machine      MachineInfo `json:"machine"`
	Findings     []Finding   `json:"findings"`
	HashChain    []string    `json:"hashChain"`
	Signature    string      `json:"signature"`
	Status       string      `json:"status"` // COMPLETE | ABORTED | ERROR
}
```

- [ ] **Step 4: Escribir `chain.go` (cadena de hashes canónica + firma)**

```go
// internal/report/chain.go
package report

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Chain encadena hallazgos: H_n = SHA256(H_{n-1} || SHA256(canonical(finding_n))).
// H_0 se deriva del nonce de sesión para atar la cadena a esa sesión.
type Chain struct {
	hashes []string
}

// NewChain crea una cadena inicializada con H_0 = SHA256(nonce).
func NewChain(nonce string) *Chain {
	h0 := sha256.Sum256([]byte(nonce))
	return &Chain{hashes: []string{hex.EncodeToString(h0[:])}}
}

// Append encadena un finding y devuelve el nuevo hash de la cadena.
func (c *Chain) Append(f Finding) (string, error) {
	body, err := canonicalFindingBytes(f)
	if err != nil {
		return "", err
	}
	fh := sha256.Sum256(body)
	prev, _ := hex.DecodeString(c.Root())
	combined := append(append([]byte{}, prev...), fh[:]...)
	next := sha256.Sum256(combined)
	h := hex.EncodeToString(next[:])
	c.hashes = append(c.hashes, h)
	return h, nil
}

// Root devuelve el último hash de la cadena.
func (c *Chain) Root() string { return c.hashes[len(c.hashes)-1] }

// Hashes devuelve la cadena completa (para Report.HashChain).
func (c *Chain) Hashes() []string { return c.hashes }

// canonicalFindingBytes serializa un Finding de forma determinista.
// encoding/json ordena las claves de structs por definición, garantizando
// bytes idénticos para findings idénticos.
func canonicalFindingBytes(f Finding) ([]byte, error) {
	return json.Marshal(f)
}

// Sign firma el root de la cadena con Ed25519 y devuelve la firma hex.
func Sign(priv ed25519.PrivateKey, root string) string {
	sig := ed25519.Sign(priv, []byte(root))
	return hex.EncodeToString(sig)
}

// Verify comprueba la firma hex del root contra la pubkey.
func Verify(pub ed25519.PublicKey, root, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(root), sig)
}
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/report/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/report/
git commit -m "feat: reporte, cadena de custodia SHA-256 y firma Ed25519"
```

---

### Task 5: Transporte — Uploader, cliente HTTP del contrato y fallback local-first

**Files:**
- Create: `internal/transport/uploader.go`
- Create: `internal/transport/httpclient.go`
- Test: `internal/transport/httpclient_test.go`

**Interfaces:**
- Consumes: `report.Report`, `report.Finding` (Task 4).
- Produces:
  - `type Session struct { SessionID, Nonce string }`
  - `type Uploader interface { OpenSession(ctx, OpenRequest) (Session, error); StreamFinding(ctx, sessionID string, seq int, f report.Finding, chainHash string) error; Complete(ctx, sessionID string, r report.Report, sigHex, root string) (verifyURL string, err error); Heartbeat(ctx, sessionID string, seq int) error }`
  - `type OpenRequest struct { AgentVersion, Pubkey string; ConsentAt time.Time; MachineInfoHash string }`
  - `func NewHTTPUploader(baseURL string, hc *http.Client) *HTTPUploader` — implementa `Uploader` con backoff exponencial (máx 3 intentos).

- [ ] **Step 1: Escribir los tests que fallan (contra httptest.Server)**

```go
// internal/transport/httpclient_test.go
package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/report"
)

func TestOpenSessionReturnsNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions" || r.Method != http.MethodPost {
			t.Errorf("request inesperado: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionId": "sess-1", "nonce": "n-123"})
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	sess, err := up.OpenSession(context.Background(), OpenRequest{
		AgentVersion: "0.1.0", Pubkey: "abcd", ConsentAt: time.Now(), MachineInfoHash: "h",
	})
	if err != nil {
		t.Fatalf("OpenSession error: %v", err)
	}
	if sess.SessionID != "sess-1" || sess.Nonce != "n-123" {
		t.Fatalf("session = %+v", sess)
	}
}

func TestStreamFindingPostsToSession(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	err := up.StreamFinding(context.Background(), "sess-1", 0, report.Finding{ID: "f1"}, "hash")
	if err != nil {
		t.Fatalf("StreamFinding error: %v", err)
	}
	if gotPath != "/api/v1/sessions/sess-1/findings" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestOpenSessionRetriesThenFails(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	up := NewHTTPUploader(srv.URL, srv.Client())
	up.retryBackoff = time.Millisecond // acelerar el test
	_, err := up.OpenSession(context.Background(), OpenRequest{AgentVersion: "0.1.0"})
	if err == nil {
		t.Fatal("esperaba error tras agotar reintentos")
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3 (máx reintentos)", calls)
	}
}
```

- [ ] **Step 2: Correr los tests para verificar que fallan**

Run: `go test ./internal/transport/`
Expected: FAIL de compilación — `undefined: NewHTTPUploader`, `undefined: OpenRequest`, etc.

- [ ] **Step 3: Escribir `uploader.go` (interfaz y tipos)**

```go
// internal/transport/uploader.go
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
```

- [ ] **Step 4: Escribir `httpclient.go` (implementación con backoff)**

```go
// internal/transport/httpclient.go
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
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/transport/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/transport/
git commit -m "feat: cliente HTTP del contrato de subida con backoff exponencial"
```

---

### Task 6: Gate de consentimiento (CLI) y hashing de identificadores

**Files:**
- Create: `internal/consent/consent.go`
- Test: `internal/consent/consent_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func CollectionSummary() []string` — líneas en lenguaje claro de qué se recolecta.
  - `func Prompt(in io.Reader, out io.Writer) (accepted bool, at time.Time)` — imprime el resumen, lee la respuesta, devuelve el timestamp de consentimiento.
  - `func HashIdentifier(nonce, raw string) string` — SHA-256 hex de `nonce||raw` (para IDs de hardware, no correlacionable entre sesiones).

- [ ] **Step 1: Escribir los tests que fallan**

```go
// internal/consent/consent_test.go
package consent

import (
	"bytes"
	"strings"
	"testing"
)

func TestPromptAcceptsYes(t *testing.T) {
	in := strings.NewReader("si\n")
	var out bytes.Buffer
	accepted, at := Prompt(in, &out)
	if !accepted {
		t.Fatal("esperaba accepted=true con 'si'")
	}
	if at.IsZero() {
		t.Fatal("esperaba timestamp de consentimiento no cero")
	}
	if !strings.Contains(out.String(), "metadatos") {
		t.Fatal("el resumen debería explicar que solo se recolectan metadatos")
	}
}

func TestPromptRejectsOther(t *testing.T) {
	accepted, _ := Prompt(strings.NewReader("no\n"), &bytes.Buffer{})
	if accepted {
		t.Fatal("esperaba accepted=false con 'no'")
	}
}

func TestHashIdentifierDependsOnNonce(t *testing.T) {
	h1 := HashIdentifier("nonce-1", "DISK-SERIAL-XYZ")
	h2 := HashIdentifier("nonce-2", "DISK-SERIAL-XYZ")
	if h1 == h2 {
		t.Fatal("el mismo ID con distinto nonce no debe ser correlacionable")
	}
	if h1 == "DISK-SERIAL-XYZ" || len(h1) != 64 {
		t.Fatalf("el hash debería ser SHA-256 hex (64 chars), got %q", h1)
	}
}
```

- [ ] **Step 2: Correr los tests para verificar que fallan**

Run: `go test ./internal/consent/`
Expected: FAIL de compilación — `undefined: Prompt`, `undefined: HashIdentifier`.

- [ ] **Step 3: Escribir `consent.go`**

```go
// internal/consent/consent.go
package consent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// CollectionSummary describe, en lenguaje claro, exactamente qué recolecta el
// agente. Nunca contenido de archivos, credenciales, historial ni mensajes.
func CollectionSummary() []string {
	return []string{
		"El agente recolecta SOLO metadatos forenses, nunca el contenido de tus archivos:",
		"  - Nombres, hashes y timestamps de programas ejecutados (Prefetch, BAM, ShimCache, AmCache).",
		"  - Rastros de borrado de archivos (historial del sistema de archivos).",
		"  - Configuración de emuladores y macros de control.",
		"NO se leen: documentos, fotos, mensajes, contraseñas, cookies ni historial de navegación.",
		"Los identificadores de hardware se anonimizan antes de salir del equipo.",
	}
}

// Prompt muestra el resumen y espera la aceptación explícita del jugador.
func Prompt(in io.Reader, out io.Writer) (bool, time.Time) {
	for _, line := range CollectionSummary() {
		fmt.Fprintln(out, line)
	}
	fmt.Fprint(out, "\n¿Aceptás la revisión? (si/no): ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false, time.Time{}
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer == "si" || answer == "sí" || answer == "s" {
		return true, time.Now()
	}
	return false, time.Time{}
}

// HashIdentifier anonimiza un ID de hardware con SHA-256(nonce||raw). Usar el
// nonce de sesión como salt evita correlacionar la misma máquina entre sesiones.
func HashIdentifier(nonce, raw string) string {
	sum := sha256.Sum256([]byte(nonce + raw))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/consent/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/consent/
git commit -m "feat: gate de consentimiento CLI y hashing de identificadores de hardware"
```

---

### Task 7: Descompresión MAM vía RtlDecompressBufferEx (ntdll)

**Files:**
- Create: `internal/winfs/compression/mam.go`
- Test: `internal/winfs/compression/mam_test.go`

**Interfaces:**
- Consumes: nada (syscall directo a ntdll).
- Produces:
  - `func DecompressMAM(data []byte) ([]byte, error)` — detecta la firma `MAM\x04` (Xpress Huffman), lee el tamaño descomprimido del header (bytes 4-8), llama a `RtlDecompressBufferEx` y devuelve el buffer descomprimido. Si no hay firma MAM, devuelve `data` intacto.
  - Constante `signatureMAM = "MAM\x04"`.

**Nota de plataforma:** este archivo solo compila en Windows (`//go:build windows`). En host no-Windows, verificar con `GOOS=windows go build ./internal/winfs/compression/`. El test se corre en Windows.

- [ ] **Step 1: Escribir el test que falla**

```go
//go:build windows

// internal/winfs/compression/mam_test.go
package compression

import (
	"bytes"
	"testing"
)

func TestDecompressMAMPassthroughWithoutSignature(t *testing.T) {
	raw := []byte("no es un archivo MAM")
	out, err := DecompressMAM(raw)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("sin firma MAM debería devolver los datos intactos")
	}
}

func TestDecompressMAMRejectsTruncatedHeader(t *testing.T) {
	_, err := DecompressMAM([]byte("MAM\x04\x01")) // header incompleto
	if err == nil {
		t.Fatal("esperaba error con header MAM truncado")
	}
}

// TestDecompressMAMRoundTrip valida contra un blob comprimido real.
// El fixture se genera en Windows con RtlCompressBuffer (ver testdata/README).
func TestDecompressMAMRoundTrip(t *testing.T) {
	compressed := loadFixture(t, "sample_mam.bin")     // blob MAM\x04 real
	expected := loadFixture(t, "sample_mam.expected")  // contenido esperado
	out, err := DecompressMAM(compressed)
	if err != nil {
		t.Fatalf("DecompressMAM error: %v", err)
	}
	if !bytes.Equal(out, expected) {
		t.Fatalf("descompresión incorrecta: got %d bytes, want %d", len(out), len(expected))
	}
}
```

- [ ] **Step 2: Crear el helper de fixtures y el README de testdata**

```go
//go:build windows

// añadir al final de internal/winfs/compression/mam_test.go
package compression

import (
	"os"
	"path/filepath"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; generar según testdata/README.md", name)
	}
	return b
}
```

Crear `internal/winfs/compression/testdata/README.md`:

```markdown
# Fixtures de compresión MAM

- `sample_mam.bin`: un buffer comprimido con firma `MAM\x04` (Xpress Huffman).
  Generar en Windows con `RtlCompressBuffer` (COMPRESSION_FORMAT_XPRESS_HUFF)
  anteponiendo el header MAM de 8 bytes: `"MAM\x04"` + uint32 LE del tamaño
  descomprimido.
- `sample_mam.expected`: el contenido original antes de comprimir.

Estos fixtures no se versionan si superan pocos KB; documentar aquí cómo regenerarlos.
```

- [ ] **Step 3: Correr el test para verificar que falla**

Run (en Windows): `go test ./internal/winfs/compression/`
Expected: FAIL de compilación — `undefined: DecompressMAM`. (El round-trip se auto-skipea sin fixture.)

- [ ] **Step 4: Escribir `mam.go`**

```go
//go:build windows

// internal/winfs/compression/mam.go
package compression

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

const signatureMAM = "MAM\x04"

// COMPRESSION_FORMAT_XPRESS_HUFF según wdm.h.
const compressionFormatXpressHuff = 0x0004

var (
	modntdll                  = windows.NewLazySystemDLL("ntdll.dll")
	procRtlDecompressBufferEx = modntdll.NewProc("RtlDecompressBufferEx")
	procRtlGetCompressionWorkSpaceSize = modntdll.NewProc("RtlGetCompressionWorkSpaceSize")
)

// DecompressMAM descomprime un buffer con firma MAM (Xpress Huffman), usado por
// los Prefetch de Win8+. Sin firma, devuelve los datos intactos.
func DecompressMAM(data []byte) ([]byte, error) {
	if len(data) < len(signatureMAM) || string(data[:len(signatureMAM)]) != signatureMAM {
		return data, nil
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("header MAM truncado: %d bytes", len(data))
	}
	uncompressedSize := binary.LittleEndian.Uint32(data[4:8])
	compressed := data[8:]

	var workspaceSize, fragmentSize uint32
	rt, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafePtr(&workspaceSize)),
		uintptr(unsafePtr(&fragmentSize)),
	)
	if rt != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize falló: 0x%x", rt)
	}
	workspace := make([]byte, workspaceSize)
	out := make([]byte, uncompressedSize)
	var finalSize uint32

	rt, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafePtr(&out[0])), uintptr(len(out)),
		uintptr(unsafePtr(&compressed[0])), uintptr(len(compressed)),
		uintptr(unsafePtr(&finalSize)),
		uintptr(unsafePtr(&workspace[0])),
	)
	if rt != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx falló: 0x%x", rt)
	}
	return out[:finalSize], nil
}
```

Crear `internal/winfs/compression/unsafe.go`:

```go
//go:build windows

package compression

import "unsafe"

// unsafePtr expone un puntero como uintptr para las llamadas syscall.
func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
```

- [ ] **Step 5: Correr los tests para verificar que pasan (en Windows)**

Run: `go test ./internal/winfs/compression/`
Expected: PASS (passthrough y truncado); round-trip PASS si el fixture existe, SKIP si no.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/compression/
git commit -m "feat: descompresión MAM (Xpress Huffman) vía RtlDecompressBufferEx"
```

---

### Task 8: Parser regf/hbin (lectura de valores del registro)

**Files:**
- Create: `internal/winfs/reghive/hive.go`
- Create: `internal/winfs/reghive/cells.go`
- Test: `internal/winfs/reghive/hive_test.go`

**Interfaces:**
- Consumes: nada (parseo binario puro).
- Produces:
  - `type Hive struct { ... }`
  - `func Open(data []byte) (*Hive, error)` — valida la firma `regf`, localiza el root cell offset.
  - `func (h *Hive) OpenKey(path string) (*Key, error)` — navega por `nk` desde el root (path con `\`).
  - `type Key struct { ... }`
  - `func (k *Key) Subkeys() ([]*Key, error)`
  - `func (k *Key) Name() string`
  - `func (k *Key) Value(name string) ([]byte, uint32, error)` — devuelve datos crudos y el tipo del valor (`vk`).
  - `func (k *Key) Values() (map[string][]byte, error)`

**Nota:** parseo binario puro, cross-platform (recibe `[]byte`). Aquí es donde más importan los tests.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/winfs/reghive/hive_test.go
package reghive

import (
	"os"
	"path/filepath"
	"testing"
)

func loadHive(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; ver testdata/README.md", name)
	}
	return b
}

func TestOpenRejectsBadSignature(t *testing.T) {
	_, err := Open([]byte("XXXX not a hive"))
	if err == nil {
		t.Fatal("esperaba error con firma inválida")
	}
}

func TestOpenValidHive(t *testing.T) {
	h, err := Open(loadHive(t, "sample.hve"))
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if h == nil {
		t.Fatal("Hive nil")
	}
}

// TestReadKnownValue navega a una clave y valor conocidos del fixture.
// El fixture y sus valores esperados se documentan en testdata/README.md.
func TestReadKnownValue(t *testing.T) {
	h, err := Open(loadHive(t, "sample.hve"))
	if err != nil {
		t.Skipf("sin fixture: %v", err)
	}
	key, err := h.OpenKey(`Select`)
	if err != nil {
		t.Fatalf("OpenKey error: %v", err)
	}
	data, typ, err := key.Value("Current")
	if err != nil {
		t.Fatalf("Value error: %v", err)
	}
	if len(data) != 4 || typ != 4 { // REG_DWORD
		t.Fatalf("valor Current inesperado: data=%v typ=%d", data, typ)
	}
}
```

- [ ] **Step 2: Crear `testdata/README.md`**

```markdown
# Fixtures de hive regf

- `sample.hve`: un hive SYSTEM real y pequeño (o recortado) para testing.
  Obtener copiando `C:\Windows\System32\config\SYSTEM` desde un snapshot VSS,
  o exportando con `reg save HKLM\SYSTEM sample.hve` en una VM de prueba.
  Documentar aquí una clave+valor conocido para el test de lectura.
  Ej.: clave `Select`, valor `Current` = REG_DWORD.
```

- [ ] **Step 3: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/reghive/`
Expected: FAIL de compilación — `undefined: Open`, `undefined: Hive`.

- [ ] **Step 4: Escribir `hive.go` (header regf + navegación de claves)**

```go
// internal/winfs/reghive/hive.go
package reghive

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	regfSignature = "regf"
	baseBlockSize = 0x1000 // el header regf ocupa 4 KiB; las celdas empiezan después
)

// Hive es un hive del registro (formato regf) parseado desde memoria.
type Hive struct {
	data          []byte // solo la región de celdas (después del base block)
	rootCellOffset uint32
}

// Open valida el header regf y localiza la celda raíz.
func Open(data []byte) (*Hive, error) {
	if len(data) < baseBlockSize {
		return nil, fmt.Errorf("hive muy corto: %d bytes", len(data))
	}
	if string(data[:4]) != regfSignature {
		return nil, fmt.Errorf("firma regf inválida: %q", data[:4])
	}
	rootOffset := binary.LittleEndian.Uint32(data[36:40])
	return &Hive{
		data:           data[baseBlockSize:],
		rootCellOffset: rootOffset,
	}, nil
}

// Key es una clave del registro (celda nk).
type Key struct {
	hive *Hive
	nk   []byte // cuerpo de la celda nk
}

// OpenKey navega desde la raíz por un path separado por "\".
func (h *Hive) OpenKey(path string) (*Key, error) {
	current := h.readKeyAt(h.rootCellOffset)
	if current == nil {
		return nil, fmt.Errorf("celda raíz inválida en offset 0x%x", h.rootCellOffset)
	}
	if path == "" {
		return current, nil
	}
	for _, part := range strings.Split(path, `\`) {
		next, err := current.subkeyByName(part)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// readKeyAt lee una celda nk en el offset dado (relativo a la región de celdas).
func (h *Hive) readKeyAt(offset uint32) *Key {
	body := h.cellBody(offset)
	if len(body) < 2 || string(body[:2]) != "nk" {
		return nil
	}
	return &Key{hive: h, nk: body}
}

// cellBody devuelve el contenido de una celda (saltando el prefijo de tamaño
// de 4 bytes). offset es relativo al inicio de la región de celdas.
func (h *Hive) cellBody(offset uint32) []byte {
	if int(offset)+4 > len(h.data) {
		return nil
	}
	size := int32(binary.LittleEndian.Uint32(h.data[offset : offset+4]))
	if size < 0 {
		size = -size // celda asignada: tamaño negativo
	}
	start := int(offset) + 4
	end := int(offset) + int(size)
	if start > len(h.data) || end > len(h.data) || start >= end {
		return nil
	}
	return h.data[start:end]
}

// Name devuelve el nombre de la clave.
func (k *Key) Name() string {
	if len(k.nk) < 76 {
		return ""
	}
	nameLen := int(binary.LittleEndian.Uint16(k.nk[72:74]))
	if 76+nameLen > len(k.nk) {
		return ""
	}
	return string(k.nk[76 : 76+nameLen])
}
```

- [ ] **Step 5: Escribir `cells.go` (subclaves y valores)**

```go
// internal/winfs/reghive/cells.go
package reghive

import (
	"encoding/binary"
	"fmt"
)

// subkeyByName busca una subclave por nombre (case-insensitive).
func (k *Key) subkeyByName(name string) (*Key, error) {
	subs, err := k.Subkeys()
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		if equalFold(s.Name(), name) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("subclave %q no encontrada", name)
}

// Subkeys devuelve las subclaves de la clave, leyendo la subkey-list.
func (k *Key) Subkeys() ([]*Key, error) {
	if len(k.nk) < 36 {
		return nil, fmt.Errorf("celda nk truncada")
	}
	subkeyCount := binary.LittleEndian.Uint32(k.nk[20:24])
	if subkeyCount == 0 {
		return nil, nil
	}
	listOffset := binary.LittleEndian.Uint32(k.nk[28:32])
	list := k.hive.cellBody(listOffset)
	if len(list) < 2 {
		return nil, fmt.Errorf("subkey-list inválida")
	}
	offsets, err := parseSubkeyList(k.hive, list)
	if err != nil {
		return nil, err
	}
	keys := make([]*Key, 0, len(offsets))
	for _, off := range offsets {
		if kk := k.hive.readKeyAt(off); kk != nil {
			keys = append(keys, kk)
		}
	}
	return keys, nil
}

// parseSubkeyList resuelve los tipos de lista lf/lh/li/ri a offsets de nk.
func parseSubkeyList(h *Hive, list []byte) ([]uint32, error) {
	sig := string(list[:2])
	switch sig {
	case "lf", "lh":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		offsets := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			base := 4 + i*8 // cada entrada: offset(4) + hash(4)
			if base+4 > len(list) {
				break
			}
			offsets = append(offsets, binary.LittleEndian.Uint32(list[base:base+4]))
		}
		return offsets, nil
	case "li":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		offsets := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(list) {
				break
			}
			offsets = append(offsets, binary.LittleEndian.Uint32(list[base:base+4]))
		}
		return offsets, nil
	case "ri":
		count := int(binary.LittleEndian.Uint16(list[2:4]))
		var all []uint32
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(list) {
				break
			}
			subListOff := binary.LittleEndian.Uint32(list[base : base+4])
			subList := h.cellBody(subListOff)
			if len(subList) < 2 {
				continue
			}
			offs, err := parseSubkeyList(h, subList)
			if err != nil {
				return nil, err
			}
			all = append(all, offs...)
		}
		return all, nil
	default:
		return nil, fmt.Errorf("tipo de subkey-list desconocido: %q", sig)
	}
}

// Value devuelve los datos crudos y el tipo de un valor por nombre.
func (k *Key) Value(name string) ([]byte, uint32, error) {
	values, types, err := k.valuesAndTypes()
	if err != nil {
		return nil, 0, err
	}
	for n, data := range values {
		if equalFold(n, name) {
			return data, types[n], nil
		}
	}
	return nil, 0, fmt.Errorf("valor %q no encontrado", name)
}

// Values devuelve todos los valores de la clave (nombre → datos crudos).
func (k *Key) Values() (map[string][]byte, error) {
	v, _, err := k.valuesAndTypes()
	return v, err
}

func (k *Key) valuesAndTypes() (map[string][]byte, map[string]uint32, error) {
	if len(k.nk) < 44 {
		return nil, nil, fmt.Errorf("celda nk truncada")
	}
	valueCount := binary.LittleEndian.Uint32(k.nk[36:40])
	values := make(map[string][]byte, valueCount)
	types := make(map[string]uint32, valueCount)
	if valueCount == 0 {
		return values, types, nil
	}
	valueListOffset := binary.LittleEndian.Uint32(k.nk[40:44])
	valueList := k.hive.cellBody(valueListOffset)
	for i := 0; i < int(valueCount); i++ {
		base := i * 4
		if base+4 > len(valueList) {
			break
		}
		vkOffset := binary.LittleEndian.Uint32(valueList[base : base+4])
		name, data, typ := k.hive.readValue(vkOffset)
		values[name] = data
		types[name] = typ
	}
	return values, types, nil
}

// readValue lee una celda vk: nombre, datos y tipo.
func (h *Hive) readValue(offset uint32) (string, []byte, uint32) {
	vk := h.cellBody(offset)
	if len(vk) < 20 || string(vk[:2]) != "vk" {
		return "", nil, 0
	}
	nameLen := int(binary.LittleEndian.Uint16(vk[2:4]))
	dataLen := binary.LittleEndian.Uint32(vk[4:8])
	dataOffset := binary.LittleEndian.Uint32(vk[8:12])
	dataType := binary.LittleEndian.Uint32(vk[12:16])

	var name string
	if nameLen > 0 && 20+nameLen <= len(vk) {
		name = string(vk[20 : 20+nameLen])
	}

	const inlineFlag = 0x80000000
	var data []byte
	if dataLen&inlineFlag != 0 {
		// datos residentes: hasta 4 bytes en el propio campo dataOffset
		n := dataLen &^ inlineFlag
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, dataOffset)
		if n > 4 {
			n = 4
		}
		data = raw[:n]
	} else {
		data = h.cellBody(dataOffset)
		if uint32(len(data)) > dataLen {
			data = data[:dataLen]
		}
	}
	return name, data, dataType
}

// equalFold compara nombres de clave/valor sin distinguir mayúsculas (ASCII).
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
```

- [ ] **Step 6: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/reghive/`
Expected: PASS (firma inválida); los tests que dependen de `sample.hve` pasan si el fixture existe, SKIP si no.

- [ ] **Step 7: Commit**

```bash
git add internal/winfs/reghive/
git commit -m "feat: parser regf/hbin con navegación de claves y lectura de valores"
```

---

### Task 9: Snapshot VSS (crear, montar, destruir)

**Files:**
- Create: `internal/winfs/vss/vss.go`
- Create: `internal/winfs/vss/vss_windows.go`
- Create: `internal/winfs/vss/vss_other.go`
- Test: `internal/winfs/vss/vss_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type Snapshot interface { DeviceObjectPath() string; Close() error }`
  - `func Create(volume string) (Snapshot, error)` — crea un shadow copy del volumen (ej. `C:\`) y devuelve el path del device object (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`). En no-Windows devuelve error `ErrUnsupported`.
  - `func PathIn(s Snapshot, relative string) string` — compone un path dentro del snapshot (ej. `Windows\appcompat\Programs\Amcache.hve`).
  - `var ErrUnsupported = errors.New("VSS solo disponible en Windows")`

**Nota:** VSS real usa WMI (`Win32_ShadowCopy.Create`) vía `wmic`/COM. Para mantener el binario sin CGO y simple, la fase 2 invoca `wmic shadowcopy call create` y parsea el ShadowID; la lógica de parseo del output es pura y testeable. La creación real se prueba a mano en Windows elevado.

- [ ] **Step 1: Escribir el test que falla (parseo del output de wmic — lógica pura)**

```go
// internal/winfs/vss/vss_test.go
package vss

import "testing"

func TestParseShadowIDFromWmic(t *testing.T) {
	out := `Ejecutando (Win32_ShadowCopy)->create()
Método de ejecución correcto.
Parámetros de salida:
instance of __PARAMETERS
{
	ReturnValue = 0;
	ShadowID = "{A1B2C3D4-0000-1111-2222-334455667788}";
};`
	id, err := parseShadowID(out)
	if err != nil {
		t.Fatalf("parseShadowID error: %v", err)
	}
	if id != "{A1B2C3D4-0000-1111-2222-334455667788}" {
		t.Fatalf("id = %q", id)
	}
}

func TestParseShadowIDMissing(t *testing.T) {
	if _, err := parseShadowID("ReturnValue = 1;"); err == nil {
		t.Fatal("esperaba error cuando no hay ShadowID")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/winfs/vss/`
Expected: FAIL de compilación — `undefined: parseShadowID`.

- [ ] **Step 3: Escribir `vss.go` (lógica de parseo, cross-platform)**

```go
// internal/winfs/vss/vss.go
package vss

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrUnsupported se devuelve al intentar crear un snapshot fuera de Windows.
var ErrUnsupported = errors.New("VSS solo disponible en Windows")

// Snapshot representa un shadow copy montado y accesible por path.
type Snapshot interface {
	DeviceObjectPath() string
	Close() error
}

var shadowIDRe = regexp.MustCompile(`ShadowID\s*=\s*"(\{[0-9A-Fa-f-]+\})"`)

// parseShadowID extrae el GUID del shadow copy del output de
// `wmic shadowcopy call create`.
func parseShadowID(wmicOutput string) (string, error) {
	m := shadowIDRe.FindStringSubmatch(wmicOutput)
	if len(m) < 2 {
		return "", fmt.Errorf("ShadowID no encontrado en el output de wmic")
	}
	return m[1], nil
}

// PathIn compone un path dentro del snapshot montado.
func PathIn(s Snapshot, relative string) string {
	return s.DeviceObjectPath() + `\` + relative
}
```

- [ ] **Step 4: Escribir `vss_windows.go` (Create real en Windows) y `vss_other.go` (error fuera)**

```go
//go:build windows

// internal/winfs/vss/vss_windows.go
package vss

import (
	"fmt"
	"os/exec"
	"strings"
)

type wmicSnapshot struct {
	shadowID   string
	devicePath string
}

func (s *wmicSnapshot) DeviceObjectPath() string { return s.devicePath }

func (s *wmicSnapshot) Close() error {
	return exec.Command("vssadmin", "delete", "shadows", "/Shadow="+s.shadowID, "/quiet").Run()
}

// Create crea un shadow copy del volumen (ej. "C:\\") vía WMI.
func Create(volume string) (Snapshot, error) {
	out, err := exec.Command("wmic", "shadowcopy", "call", "create",
		"Volume="+volume).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wmic shadowcopy create falló: %w", err)
	}
	id, err := parseShadowID(string(out))
	if err != nil {
		return nil, err
	}
	device, err := resolveDevicePath(id)
	if err != nil {
		return nil, err
	}
	return &wmicSnapshot{shadowID: id, devicePath: device}, nil
}

// resolveDevicePath obtiene el DeviceObject del shadow copy vía vssadmin.
func resolveDevicePath(shadowID string) (string, error) {
	out, err := exec.Command("vssadmin", "list", "shadows", "/Shadow="+shadowID).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("vssadmin list shadows falló: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Shadow Copy Volume") || strings.Contains(line, "volumen de instantánea") {
			if idx := strings.Index(line, `\\?\GLOBALROOT`); idx >= 0 {
				return strings.TrimSpace(line[idx:]), nil
			}
		}
	}
	return "", fmt.Errorf("DeviceObject no encontrado para %s", shadowID)
}
```

Crear `internal/winfs/vss/vss_other.go`:

```go
//go:build !windows

package vss

// Create no está soportado fuera de Windows.
func Create(volume string) (Snapshot, error) { return nil, ErrUnsupported }
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/winfs/vss/`
Expected: PASS (parseo). Verificar build Windows: `GOOS=windows go build ./internal/winfs/vss/`.

- [ ] **Step 6: Commit**

```bash
git add internal/winfs/vss/
git commit -m "feat: creación y destrucción de snapshots VSS vía WMI"
```

---

### Task 10: Colector Prefetch

**Files:**
- Create: `internal/collector/prefetch/prefetch.go`
- Create: `internal/collector/prefetch/parse.go`
- Test: `internal/collector/prefetch/parse_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact` (Task 1); `compression.DecompressMAM` (Task 7).
- Produces:
  - `type Collector struct { Dir string }` — implementa `collector.Collector`; `Dir` default `C:\Windows\Prefetch`.
  - `func New() *Collector`
  - `type Entry struct { ExecutableName string; PathHash string; RunCount uint32; LastRunTimes []time.Time; Volumes []string; LoadedFiles []string; Version uint32 }`
  - `func parsePrefetch(data []byte) (Entry, error)` — descomprime MAM si aplica y parsea el header por versión (v23/v26/v30/v31).

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/prefetch/parse_test.go
package prefetch

import (
	"os"
	"path/filepath"
	"testing"
)

func loadPF(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s ausente; ver testdata/README.md", name)
	}
	return b
}

func TestParsePrefetchRejectsGarbage(t *testing.T) {
	if _, err := parsePrefetch([]byte("no soy un pf")); err == nil {
		t.Fatal("esperaba error con datos inválidos")
	}
}

// TestParsePrefetchWin10 valida contra un .pf real de Win10 (v30, comprimido).
func TestParsePrefetchWin10(t *testing.T) {
	e, err := parsePrefetch(loadPF(t, "NOTEPAD.EXE-v30.pf"))
	if err != nil {
		t.Fatalf("parsePrefetch error: %v", err)
	}
	if e.ExecutableName == "" {
		t.Fatal("ExecutableName vacío")
	}
	if e.Version != 30 {
		t.Fatalf("Version = %d, want 30", e.Version)
	}
	if e.RunCount == 0 {
		t.Fatal("RunCount = 0, se esperaba > 0 en el fixture")
	}
}
```

- [ ] **Step 2: Crear `testdata/README.md`**

```markdown
# Fixtures de Prefetch

Copiar archivos reales de `C:\Windows\Prefetch\*.pf` desde una VM de prueba:
- `NOTEPAD.EXE-v30.pf`: Win10 (formato v30, comprimido MAM).
- Opcional: fixtures v23 (Win7 sin comprimir), v26 (Win8.1), v31 (Win11).

Documentar aquí los valores esperados de cada fixture (nombre, run count, versión).
```

- [ ] **Step 3: Correr el test para verificar que falla**

Run (en Windows): `go test ./internal/collector/prefetch/`
Expected: FAIL de compilación — `undefined: parsePrefetch`, `undefined: Entry`.

- [ ] **Step 4: Escribir `parse.go`**

```go
//go:build windows

// internal/collector/prefetch/parse.go
package prefetch

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/telagem/agent-windows/internal/winfs/compression"
)

// Entry es un archivo Prefetch parseado.
type Entry struct {
	ExecutableName string
	PathHash       string
	RunCount       uint32
	LastRunTimes   []time.Time
	Volumes        []string
	LoadedFiles    []string
	Version        uint32
}

// parsePrefetch descomprime (si es MAM) y parsea un .pf según su versión.
func parsePrefetch(raw []byte) (Entry, error) {
	data, err := compression.DecompressMAM(raw)
	if err != nil {
		return Entry{}, fmt.Errorf("descompresión MAM: %w", err)
	}
	if len(data) < 84 || string(data[4:8]) != "SCCA" {
		return Entry{}, fmt.Errorf("firma SCCA ausente")
	}
	version := binary.LittleEndian.Uint32(data[0:4])

	// Nombre del ejecutable: UTF-16LE en offset 0x10, hasta 60 bytes.
	name := decodeUTF16(data[0x10:0x4C])

	e := Entry{
		ExecutableName: name,
		Version:        version,
	}

	// Offsets de metadatos según versión.
	var runCountOffset, lastRunOffset int
	switch version {
	case 23: // Win7
		lastRunOffset = 0x80
		runCountOffset = 0x98
	case 26: // Win8.1
		lastRunOffset = 0x80
		runCountOffset = 0xD0
	case 30, 31: // Win10 / Win11
		lastRunOffset = 0x80
		runCountOffset = 0xD0
	default:
		return Entry{}, fmt.Errorf("versión de prefetch no soportada: %d", version)
	}

	if runCountOffset+4 <= len(data) {
		e.RunCount = binary.LittleEndian.Uint32(data[runCountOffset : runCountOffset+4])
	}
	// Hasta 8 timestamps FILETIME de 8 bytes.
	for i := 0; i < 8; i++ {
		off := lastRunOffset + i*8
		if off+8 > len(data) {
			break
		}
		ft := binary.LittleEndian.Uint64(data[off : off+8])
		if ft == 0 {
			continue
		}
		e.LastRunTimes = append(e.LastRunTimes, filetimeToTime(ft))
	}
	return e, nil
}

// decodeUTF16 decodifica una cadena UTF-16LE terminada en nulo.
func decodeUTF16(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// filetimeToTime convierte un FILETIME (100ns desde 1601) a time.Time UTC.
func filetimeToTime(ft uint64) time.Time {
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600 // segundos entre 1601 y 1970
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}
```

- [ ] **Step 5: Escribir `prefetch.go` (el colector)**

```go
//go:build windows

// internal/collector/prefetch/prefetch.go
package prefetch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
)

// Collector recolecta y parsea los archivos Prefetch del sistema.
type Collector struct {
	Dir string
}

// New crea el colector con el directorio Prefetch por defecto.
func New() *Collector {
	return &Collector{Dir: `C:\Windows\Prefetch`}
}

func (c *Collector) Name() string  { return "prefetch" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	pattern := filepath.Join(c.Dir, "*.pf")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var artifacts []collector.Artifact
	for _, f := range files {
		select {
		case <-ctx.Done():
			return artifacts, ctx.Err()
		default:
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue // archivo inaccesible: se omite, no se aborta
		}
		entry, err := parsePrefetch(raw)
		if err != nil {
			continue
		}
		data, _ := json.Marshal(entry)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "prefetch",
			Source:    f,
			Data:      data,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}
```

- [ ] **Step 6: Correr los tests para verificar que pasan (en Windows)**

Run: `go test ./internal/collector/prefetch/`
Expected: PASS (garbage rechazado); el test v30 pasa con fixture, SKIP sin él.

- [ ] **Step 7: Commit**

```bash
git add internal/collector/prefetch/
git commit -m "feat: colector Prefetch con parseo v23/v26/v30/v31 y descompresión MAM"
```

---

### Task 11: Colector BAM

**Files:**
- Create: `internal/collector/bam/bam.go`
- Test: `internal/collector/bam/bam_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact` (Task 1); `reghive.Open`, `reghive.Key` (Task 8).
- Produces:
  - `type Collector struct { HivePath string }` — implementa `collector.Collector`; `HivePath` default apunta al hive SYSTEM (idealmente vía VSS).
  - `func New(systemHivePath string) *Collector`
  - `type Entry struct { SID string; ExecutablePath string; LastExecution time.Time }`
  - `func parseBAM(h *reghive.Hive) ([]Entry, error)` — recorre `ControlSet001\Services\bam\State\UserSettings\{SID}` y decodifica cada valor (path → FILETIME de 8 bytes al inicio del dato).

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/bam/bam_test.go
package bam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

func TestParseBAMFromFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "system_bam.hve"))
	if err != nil {
		t.Skipf("fixture ausente: %v", err)
	}
	h, err := reghive.Open(b)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	entries, err := parseBAM(h)
	if err != nil {
		t.Fatalf("parseBAM error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("esperaba al menos una entrada BAM en el fixture")
	}
	for _, e := range entries {
		if e.ExecutablePath == "" || e.SID == "" {
			t.Fatalf("entrada incompleta: %+v", e)
		}
	}
}

func TestDecodeBAMValueExtractsFiletime(t *testing.T) {
	// 8 bytes de FILETIME + relleno; se valida que no sea el cero epoch.
	raw := make([]byte, 24)
	// FILETIME correspondiente a un instante > 1601.
	for i, v := range []byte{0x00, 0x80, 0x3e, 0xd5, 0xde, 0xb1, 0x9d, 0x01} {
		raw[i] = v
	}
	ts, ok := decodeBAMValue(raw)
	if !ok {
		t.Fatal("esperaba decodificación válida")
	}
	if ts.IsZero() {
		t.Fatal("timestamp no debería ser cero")
	}
}
```

- [ ] **Step 2: Crear `testdata/README.md`**

```markdown
# Fixtures de BAM

- `system_bam.hve`: hive SYSTEM (o recorte) con al menos una entrada bajo
  `ControlSet001\Services\bam\State\UserSettings\{SID}`. Obtener de una VM de
  prueba con `reg save HKLM\SYSTEM system_bam.hve` (elevado). Documentar aquí
  el SID y un path esperado.
```

- [ ] **Step 3: Correr el test para verificar que falla**

Run: `go test ./internal/collector/bam/`
Expected: FAIL de compilación — `undefined: parseBAM`, `undefined: decodeBAMValue`.

- [ ] **Step 4: Escribir `bam.go`**

```go
// internal/collector/bam/bam.go
package bam

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

// Entry es una ejecución registrada por BAM (Background Activity Moderator).
type Entry struct {
	SID            string    `json:"sid"`
	ExecutablePath string    `json:"executablePath"`
	LastExecution  time.Time `json:"lastExecution"`
}

// Collector lee las entradas BAM del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "bam" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := readFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	entries, err := parseBAM(h)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "bam",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

// parseBAM recorre los SID bajo UserSettings y decodifica sus valores.
func parseBAM(h *reghive.Hive) ([]Entry, error) {
	base := `ControlSet001\Services\bam\State\UserSettings`
	root, err := h.OpenKey(base)
	if err != nil {
		// Algunos sistemas usan CurrentControlSet resuelto a ControlSet002.
		root, err = h.OpenKey(`ControlSet002\Services\bam\State\UserSettings`)
		if err != nil {
			return nil, err
		}
	}
	sidKeys, err := root.Subkeys()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, sidKey := range sidKeys {
		sid := sidKey.Name()
		values, err := sidKey.Values()
		if err != nil {
			continue
		}
		for path, raw := range values {
			ts, ok := decodeBAMValue(raw)
			if !ok {
				continue
			}
			entries = append(entries, Entry{SID: sid, ExecutablePath: path, LastExecution: ts})
		}
	}
	return entries, nil
}

// decodeBAMValue extrae el FILETIME de los primeros 8 bytes del valor BAM.
func decodeBAMValue(raw []byte) (time.Time, bool) {
	if len(raw) < 8 {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(raw[:8])
	if ft == 0 {
		return time.Time{}, false
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC(), true
}
```

Crear `internal/collector/bam/io.go` (aislar la lectura de archivo para testeo):

```go
package bam

import "os"

// readFile se aísla como variable para poder sustituirla en tests si hace falta.
var readFile = os.ReadFile
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/bam/`
Expected: PASS (`decodeBAMValue`); `parseBAM` pasa con fixture, SKIP sin él.

- [ ] **Step 6: Commit**

```bash
git add internal/collector/bam/
git commit -m "feat: colector BAM (path + última ejecución por SID)"
```

---

### Task 12: Colector ShimCache (AppCompatCache)

**Files:**
- Create: `internal/collector/shimcache/shimcache.go`
- Create: `internal/collector/shimcache/parse.go`
- Test: `internal/collector/shimcache/parse_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact` (Task 1); `reghive.Open` (Task 8).
- Produces:
  - `type Collector struct { HivePath string }` — implementa `collector.Collector`.
  - `func New(systemHivePath string) *Collector`
  - `type Entry struct { Path string; ModifiedTime time.Time }`
  - `func parseAppCompatCache(blob []byte) ([]Entry, error)` — detecta la versión por el header (Win10/11 usa el magic `0x34` con entradas `10ts`) y parsea la lista.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/shimcache/parse_test.go
package shimcache

import (
	"encoding/binary"
	"testing"
)

func TestParseAppCompatCacheWin10Signature(t *testing.T) {
	// Header Win10: offset 0x30 al primer registro; magic "10ts" en cada entrada.
	blob := make([]byte, 0x30)
	binary.LittleEndian.PutUint32(blob[0:4], 0x34) // offset de header Win10

	entry := buildWin10Entry("C:\\Windows\\System32\\evil.exe", 0x01D9B1DED53E8000)
	blob = append(blob, entry...)

	entries, err := parseAppCompatCache(blob)
	if err != nil {
		t.Fatalf("parseAppCompatCache error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Path != "C:\\Windows\\System32\\evil.exe" {
		t.Fatalf("path = %q", entries[0].Path)
	}
}

func TestParseAppCompatCacheRejectsEmpty(t *testing.T) {
	if _, err := parseAppCompatCache(nil); err == nil {
		t.Fatal("esperaba error con blob vacío")
	}
}

// buildWin10Entry construye una entrada "10ts" para el test.
func buildWin10Entry(path string, filetime uint64) []byte {
	pathUTF16 := make([]byte, 0, len(path)*2)
	for _, r := range path {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(r))
		pathUTF16 = append(pathUTF16, b[:]...)
	}
	e := []byte("10ts")
	e = append(e, 0, 0, 0, 0) // unknown
	dataSize := 12 + 2 + len(pathUTF16)
	sz := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz, uint32(dataSize))
	e = append(e, sz...)
	pl := make([]byte, 2)
	binary.LittleEndian.PutUint16(pl, uint16(len(pathUTF16)))
	e = append(e, pl...)
	e = append(e, pathUTF16...)
	ft := make([]byte, 8)
	binary.LittleEndian.PutUint64(ft, filetime)
	e = append(e, ft...)
	dsz := make([]byte, 4)
	e = append(e, dsz...) // data size = 0
	return e
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/shimcache/`
Expected: FAIL de compilación — `undefined: parseAppCompatCache`.

- [ ] **Step 3: Escribir `parse.go`**

```go
// internal/collector/shimcache/parse.go
package shimcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Entry es un ejecutable visto por el sistema según ShimCache.
type Entry struct {
	Path         string    `json:"path"`
	ModifiedTime time.Time `json:"modifiedTime"`
}

var win10Magic = []byte("10ts")

// parseAppCompatCache parsea el blob binario del valor AppCompatCache.
// Implementa el formato Win10/Win11 (entradas "10ts").
func parseAppCompatCache(blob []byte) ([]Entry, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob AppCompatCache vacío o truncado")
	}
	headerOffset := int(binary.LittleEndian.Uint32(blob[0:4]))
	if headerOffset <= 0 || headerOffset > len(blob) {
		return nil, fmt.Errorf("offset de header inválido: %d", headerOffset)
	}
	var entries []Entry
	pos := headerOffset
	for pos+12 <= len(blob) {
		if !bytes.Equal(blob[pos:pos+4], win10Magic) {
			break
		}
		// magic(4) + unknown(4) + dataSize(4)
		dataSize := int(binary.LittleEndian.Uint32(blob[pos+8 : pos+12]))
		recStart := pos + 12
		if recStart+dataSize > len(blob) {
			break
		}
		rec := blob[recStart : recStart+dataSize]
		e, err := parseWin10Record(rec)
		if err == nil {
			entries = append(entries, e)
		}
		pos = recStart + dataSize
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no se parsearon entradas ShimCache")
	}
	return entries, nil
}

// parseWin10Record parsea un registro "10ts": pathLen(2) + path + FILETIME(8).
func parseWin10Record(rec []byte) (Entry, error) {
	if len(rec) < 2 {
		return Entry{}, fmt.Errorf("registro truncado")
	}
	pathLen := int(binary.LittleEndian.Uint16(rec[0:2]))
	if 2+pathLen+8 > len(rec) {
		return Entry{}, fmt.Errorf("registro truncado (path)")
	}
	path := decodeUTF16(rec[2 : 2+pathLen])
	ft := binary.LittleEndian.Uint64(rec[2+pathLen : 2+pathLen+8])
	return Entry{Path: path, ModifiedTime: filetimeToTime(ft)}, nil
}

func decodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}
```

- [ ] **Step 4: Escribir `shimcache.go` (el colector)**

```go
// internal/collector/shimcache/shimcache.go
package shimcache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

// Collector lee el AppCompatCache del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "shimcache" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	blob, err := readAppCompatCacheValue(h)
	if err != nil {
		return nil, err
	}
	entries, err := parseAppCompatCache(blob)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "shimcache",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

func readAppCompatCacheValue(h *reghive.Hive) ([]byte, error) {
	for _, cs := range []string{"ControlSet001", "ControlSet002"} {
		key, err := h.OpenKey(cs + `\Control\Session Manager\AppCompatCache`)
		if err != nil {
			continue
		}
		blob, _, err := key.Value("AppCompatCache")
		if err == nil {
			return blob, nil
		}
	}
	return nil, fmt.Errorf("valor AppCompatCache no encontrado")
}
```

- [ ] **Step 5: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/shimcache/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/collector/shimcache/
git commit -m "feat: colector ShimCache (AppCompatCache Win10/11)"
```

---

### Task 13: Colector AmCache

**Files:**
- Create: `internal/collector/amcache/amcache.go`
- Test: `internal/collector/amcache/amcache_test.go`

**Interfaces:**
- Consumes: `collector.Collector`, `collector.Artifact` (Task 1); `reghive.Open`, `reghive.Key` (Task 8).
- Produces:
  - `type Collector struct { HivePath string }` — implementa `collector.Collector`; `HivePath` default `C:\Windows\appcompat\Programs\Amcache.hve` (copiado vía VSS).
  - `func New(amcacheHivePath string) *Collector`
  - `type Entry struct { SHA1 string; Path string; LinkDate time.Time }`
  - `func parseAmcache(h *reghive.Hive) ([]Entry, error)` — recorre `Root\InventoryApplicationFile\*`, extrae `LowerCaseLongPath`, `FileId` (SHA-1) y `LinkDate`.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/collector/amcache/amcache_test.go
package amcache

import "testing"

func TestNormalizeFileIDStripsPrefix(t *testing.T) {
	// FileId en AmCache viene como "0000" + SHA-1 (44 chars total).
	raw := "0000aabbccddeeff00112233445566778899aabb"
	got := normalizeFileID(raw)
	if got != "aabbccddeeff00112233445566778899aabb" {
		t.Fatalf("normalizeFileID = %q", got)
	}
}

func TestNormalizeFileIDShortReturnsAsIs(t *testing.T) {
	if got := normalizeFileID("abc"); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/collector/amcache/`
Expected: FAIL de compilación — `undefined: normalizeFileID`.

- [ ] **Step 3: Escribir `amcache.go`**

```go
// internal/collector/amcache/amcache.go
package amcache

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

// Entry es un ejecutable registrado por AmCache. El SHA-1 sobrevive al borrado
// del archivo, lo que lo hace crítico para el forense.
type Entry struct {
	SHA1     string    `json:"sha1"`
	Path     string    `json:"path"`
	LinkDate time.Time `json:"linkDate"`
}

// Collector lee InventoryApplicationFile del Amcache.hve.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al Amcache.hve dado (copiado vía VSS).
func New(amcacheHivePath string) *Collector {
	return &Collector{HivePath: amcacheHivePath}
}

func (c *Collector) Name() string  { return "amcache" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	entries, err := parseAmcache(h)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "amcache",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

// parseAmcache recorre InventoryApplicationFile extrayendo hash, path y fecha.
func parseAmcache(h *reghive.Hive) ([]Entry, error) {
	root, err := h.OpenKey(`Root\InventoryApplicationFile`)
	if err != nil {
		return nil, err
	}
	subs, err := root.Subkeys()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, s := range subs {
		vals, err := s.Values()
		if err != nil {
			continue
		}
		e := Entry{}
		if p, ok := vals["LowerCaseLongPath"]; ok {
			e.Path = decodeUTF16(p)
		}
		if fid, ok := vals["FileId"]; ok {
			e.SHA1 = normalizeFileID(decodeUTF16(fid))
		}
		if ld, ok := vals["LinkDate"]; ok {
			e.LinkDate = parseLinkDate(decodeUTF16(ld))
		}
		if e.Path != "" || e.SHA1 != "" {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// normalizeFileID quita el prefijo "0000" que AmCache antepone al SHA-1.
func normalizeFileID(raw string) string {
	if len(raw) == 44 && strings.HasPrefix(raw, "0000") {
		return raw[4:]
	}
	return raw
}

// parseLinkDate parsea el LinkDate de AmCache ("MM/DD/YYYY HH:MM:SS").
func parseLinkDate(s string) time.Time {
	t, err := time.Parse("01/02/2006 15:04:05", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}

// decodeUTF16 decodifica REG_SZ (UTF-16LE) a string.
func decodeUTF16(b []byte) string {
	var sb []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		sb = append(sb, rune(c))
	}
	return string(sb)
}
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/collector/amcache/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/amcache/
git commit -m "feat: colector AmCache (SHA-1, path, LinkDate)"
```

---

### Task 14: Entrypoint — orquestación, elevación, timeout y reporte

**Files:**
- Create: `cmd/agent/main.go`
- Create: `internal/agent/agent.go`
- Test: `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: `privilege` (Task 3), `collector.Run` (Task 2), `report` (Task 4), `transport` (Task 5), `consent` (Task 6), y los colectores (Tasks 10-13).
- Produces:
  - `type Options struct { Timeout time.Duration; ServerURL string; Version string }`
  - `func Run(ctx context.Context, opts Options, up transport.Uploader) (report.Report, error)` — orquesta: consentimiento → sesión → colectores → findings encadenados en streaming → firma → complete. Testeable con un `Uploader` fake.

- [ ] **Step 1: Escribir el test que falla**

```go
// internal/agent/agent_test.go
package agent

import (
	"context"
	"testing"
	"time"

	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
)

type fakeUploader struct {
	findings int
	completed bool
}

func (f *fakeUploader) OpenSession(ctx context.Context, req transport.OpenRequest) (transport.Session, error) {
	return transport.Session{SessionID: "s1", Nonce: "n1"}, nil
}
func (f *fakeUploader) StreamFinding(ctx context.Context, id string, seq int, fi report.Finding, ch string) error {
	f.findings++
	return nil
}
func (f *fakeUploader) Complete(ctx context.Context, id string, r report.Report, sig, root string) (string, error) {
	f.completed = true
	return "https://verify/s1", nil
}
func (f *fakeUploader) Heartbeat(ctx context.Context, id string, seq int) error { return nil }

func TestRunProducesSignedReport(t *testing.T) {
	up := &fakeUploader{}
	opts := Options{Timeout: time.Minute, ServerURL: "http://x", Version: "test"}
	rep, err := runWithCollectors(context.Background(), opts, up, testCollectors(), true)
	if err != nil {
		t.Fatalf("runWithCollectors error: %v", err)
	}
	if rep.Signature == "" {
		t.Fatal("el reporte debería estar firmado")
	}
	if rep.Status != "COMPLETE" {
		t.Fatalf("Status = %q, want COMPLETE", rep.Status)
	}
	if len(rep.HashChain) < 1 {
		t.Fatal("la cadena de hashes no debería estar vacía")
	}
	if !up.completed {
		t.Fatal("Complete no fue llamado")
	}
}

func TestRunAbortsWithoutConsent(t *testing.T) {
	up := &fakeUploader{}
	opts := Options{Timeout: time.Minute, Version: "test"}
	_, err := runWithCollectors(context.Background(), opts, up, testCollectors(), false)
	if err == nil {
		t.Fatal("esperaba error si no hay consentimiento")
	}
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/agent/`
Expected: FAIL de compilación — `undefined: runWithCollectors`, `undefined: Options`, `undefined: testCollectors`.

- [ ] **Step 3: Escribir `agent.go`**

```go
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
)

// Options configura una ejecución del agente.
type Options struct {
	Timeout   time.Duration
	ServerURL string
	Version   string
	Machine   report.MachineInfo // estado de la máquina (elevación, VM, OS, uptime)
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

	results := collector.Run(ctx, collectors)
	seq := 0
	for _, res := range results {
		findings := resultToFindings(res)
		for _, f := range findings {
			chainHash, err := chain.Append(f)
			if err != nil {
				continue
			}
			rep.Findings = append(rep.Findings, f)
			_ = up.StreamFinding(ctx, sess.SessionID, seq, f, chainHash)
			seq++
		}
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

// resultToFindings traduce el resultado de un colector a findings. Un colector
// caído se convierte en un finding INFO; los artefactos se resumen como INFO
// de EXECUTION (la correlación real es fase 4).
func resultToFindings(res collector.Result) []report.Finding {
	if res.Err != nil {
		return []report.Finding{{
			ID:         "collector-error-" + res.Collector,
			Category:   "ANTI_FORENSIC",
			Severity:   "INFO",
			Confidence: 0.1,
			Title:      "Colector " + res.Collector + " falló",
			Evidence:   res.Err.Error(),
			Artifact:   res.Collector,
		}}
	}
	findings := make([]report.Finding, 0, len(res.Artifacts))
	for i, a := range res.Artifacts {
		findings = append(findings, report.Finding{
			ID:         fmt.Sprintf("%s-%d", res.Collector, i),
			Category:   "EXECUTION",
			Severity:   "INFO",
			Confidence: 0.0,
			Title:      "Artefacto " + a.Type,
			Evidence:   string(a.Data),
			Artifact:   a.Source,
		})
	}
	return findings
}
```

Crear `internal/agent/collectors_test_helpers_test.go`:

```go
package agent

import (
	"context"

	"github.com/telagem/agent-windows/internal/collector"
)

type memCollector struct{}

func (memCollector) Name() string  { return "mem" }
func (memCollector) Priority() int { return collector.PriorityVolatile }
func (memCollector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	return []collector.Artifact{{Type: "mem", Source: "test", Data: []byte(`{"x":1}`)}}, nil
}

func testCollectors() []collector.Collector { return []collector.Collector{memCollector{}} }
```

- [ ] **Step 4: Correr los tests para verificar que pasan**

Run: `go test ./internal/agent/`
Expected: PASS.

- [ ] **Step 5: Escribir `cmd/agent/main.go`**

```go
//go:build windows

// cmd/agent/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/telagem/agent-windows/internal/agent"
	"github.com/telagem/agent-windows/internal/consent"
	"github.com/telagem/agent-windows/internal/privilege"
	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
	"golang.org/x/sys/windows"
)

const agentVersion = "0.1.0"

// uptimeMinutes devuelve el uptime del sistema en minutos vía GetTickCount64.
// Un uptime bajo puede indicar un reinicio para limpiar artefactos volátiles.
func uptimeMinutes() int {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	ms, _, _ := getTickCount64.Call()
	return int(ms / 1000 / 60)
}

func main() {
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout global del escaneo")
	serverURL := flag.String("server", "", "URL base del servidor de verificación")
	flag.Parse()

	elevated, err := privilege.IsElevated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo verificar la elevación: %v\n", err)
		os.Exit(2)
	}
	if !elevated {
		fmt.Fprintln(os.Stderr, "ERROR: el agente requiere privilegios de administrador. "+
			"Cerralo y volvé a ejecutarlo como administrador (clic derecho → Ejecutar como administrador).")
		os.Exit(1)
	}

	vm := privilege.DetectVM()
	if vm.Detected {
		fmt.Fprintf(os.Stderr, "AVISO: entorno de VM detectado (%v). El escaneo continúa.\n", vm.Reasons)
	}

	accepted, _ := consent.Prompt(os.Stdin, os.Stdout)
	if !accepted {
		fmt.Fprintln(os.Stderr, "Escaneo cancelado: no se otorgó consentimiento.")
		os.Exit(1)
	}

	up := transport.NewHTTPUploader(*serverURL, nil)
	opts := agent.Options{
		Timeout:   *timeout,
		ServerURL: *serverURL,
		Version:   agentVersion,
		Machine: report.MachineInfo{
			OS:            runtime.GOOS,
			UptimeMinutes: uptimeMinutes(),
			Elevated:      elevated,
			VM:            vm.Detected,
			VMReasons:     vm.Reasons,
		},
	}

	rep, err := agent.RunLive(context.Background(), opts, up)
	if err != nil {
		fmt.Fprintf(os.Stderr, "el escaneo terminó con error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Escaneo %s: %d hallazgos, estado %s\n", rep.SessionID, len(rep.Findings), rep.Status)
}
```

- [ ] **Step 6: Escribir `RunLive` (colectores reales) en `internal/agent/live_windows.go`**

```go
//go:build windows

// internal/agent/live_windows.go
package agent

import (
	"context"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/collector/amcache"
	"github.com/telagem/agent-windows/internal/collector/bam"
	"github.com/telagem/agent-windows/internal/collector/prefetch"
	"github.com/telagem/agent-windows/internal/collector/shimcache"
	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
	"github.com/telagem/agent-windows/internal/winfs/vss"
)

// RunLive arma los colectores reales (tomando hives desde un snapshot VSS) y
// ejecuta el flujo completo con consentimiento ya otorgado por el CLI.
func RunLive(ctx context.Context, opts Options, up transport.Uploader) (report.Report, error) {
	systemHive := `C:\Windows\System32\config\SYSTEM`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
	}

	collectors := []collector.Collector{
		prefetch.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}
```

- [ ] **Step 7: Verificar el build de Windows y correr los tests**

Run: `GOOS=windows go build ./...`
Expected: compila sin errores.
Run: `go test ./...`
Expected: PASS (los tests Windows-only se corren en Windows; los cross-platform en cualquier host).

- [ ] **Step 8: Commit**

```bash
git add cmd/ internal/agent/
git commit -m "feat: entrypoint con elevación, consentimiento, orquestación y RunLive vía VSS"
```

---

### Task 15: GitHub Actions — build reproducible

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: todo el árbol del módulo.
- Produces: workflow que compila `windows/amd64` sin CGO y corre los tests.

- [ ] **Step 1: Escribir el workflow**

```yaml
# .github/workflows/build.yml
name: build
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test-and-build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Test
        run: go test ./...
      - name: Build
        env:
          CGO_ENABLED: '0'
          GOOS: windows
          GOARCH: amd64
        run: go build -trimpath -o agent.exe ./cmd/agent
      - uses: actions/upload-artifact@v4
        with:
          name: agent-windows-amd64
          path: agent.exe
```

- [ ] **Step 2: Escribir `README.md`**

```markdown
# agent-windows

Agente forense por consentimiento (telagem/screenshare) para verificación
anticheat en la comunidad de Free Fire. Análisis forense post-hoc: reconstruye
qué se ejecutó y qué se borró en la máquina, con el jugador presente y previa
aceptación explícita.

## Build

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o agent.exe ./cmd/agent
```

## Ejecución

Requiere privilegios de administrador. Clic derecho → Ejecutar como administrador.

```
agent.exe -server https://<servidor-de-verificacion> -timeout 10m
```

## Privacidad

El agente recolecta **solo metadatos forenses** (nombres, hashes, timestamps,
paths). Nunca contenido de archivos, credenciales, historial ni mensajes. Los
identificadores de hardware se anonimizan antes de salir del equipo. El código
es público y el binario se compila de forma reproducible vía GitHub Actions.
```

- [ ] **Step 3: Commit**

```bash
git add .github/ README.md
git commit -m "chore: CI de build/test para windows-amd64 y README"
```

---

## Notas de ejecución para las fases siguientes (no implementar ahora)

- **Fase 3** (USN Journal, MFT): nuevos colectores bajo `internal/collector/`, más una primitiva `winfs/ntfs` para acceso raw a `\\.\C:` (parseo de boot sector + MFT). Reutilizan `collector.Collector` y `filetimeToTime`.
- **Fase 4** (correlación): motor de reglas declarativo cargado desde YAML embebido; consume el `ArtifactStore` agregado de todos los colectores y produce `Finding` con severidad y confianza reales (reemplaza el `resultToFindings` placeholder de la Task 14).
- **Fase 5** (emuladores + ADB) y **Fase 6** (HTML timeline): specs y planes propios.

Cuando la fase 4 aterrice, `resultToFindings` en `internal/agent/agent.go` se sustituye por el motor de reglas: hoy emite findings INFO neutros a propósito, para no acusar sin correlación.
