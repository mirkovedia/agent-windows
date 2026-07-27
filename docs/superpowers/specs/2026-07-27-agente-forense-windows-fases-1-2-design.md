# Agente forense Windows (telagem/screenshare) — Diseño Fases 1 y 2

**Fecha:** 2026-07-27
**Alcance de este documento:** Fase 1 (esqueleto + interfaces núcleo + reporte firmado Ed25519) y Fase 2 (colectores de ejecución: Prefetch, BAM, ShimCache, AmCache).
**Fuera de alcance (specs posteriores):** Fase 3 (USN Journal, MFT), Fase 4 (motor de correlación), Fase 5 (emuladores + ADB), Fase 6 (HTML con línea de tiempo). Sus interfaces se dejan preparadas acá.

---

## 1. Contexto y premisa

Agente forense en Go para Windows, parte de un sistema de verificación anticheat **por consentimiento** para una comunidad competitiva de Free Fire. Modelo **telagem/screenshare**: el jugador acepta la revisión como condición para competir; un analista ejecuta el agente en la máquina del jugador, con el jugador presente.

No es anticheat en tiempo real: no hookea el juego, no hace ingeniería inversa. Es **análisis forense post-hoc con consentimiento**. La premisa central del diseño: **el objetivo no es encontrar el cheat abierto, es detectar la destrucción de evidencia.** Un sistema demasiado limpio es más sospechoso que uno sucio.

## 2. Requisitos de ejecución

- Compilado a binario único `windows/amd64`, **sin CGO**. Acceso de bajo nivel vía `golang.org/x/sys/windows`.
- Requiere elevación (UAC). Si no está elevado → aborta con mensaje claro.
- Detecta VM/sandbox y lo **registra** (no aborta, solo lo marca).
- Timeout global configurable, default 10 minutos.
- Código fuente público, build reproducible vía GitHub Actions, binario firmado. Sin dependencias externas en runtime.

## 3. Decisiones de arquitectura resueltas en brainstorming

| Decisión | Resolución | Razón |
|---|---|---|
| Servidor de reporte | Se diseña el **contrato cliente-servidor** acá; el server se implementa en su propio ciclo. El agente es local-first. | Permite construir el agente completo sin bloquear en el backend. |
| Lectura de hives (BAM/ShimCache/AmCache) | **Parser regf propio + snapshot VSS** desde la fase 2. | Forense correcto: ve entradas eliminadas y no se bloquea por hives en uso. Es lo que exige el spec. |
| Descompresión MAM de Prefetch | **RtlDecompressBufferEx vía syscall a ntdll**. El parseo del formato v23–v31 es propio. | El agente corre en vivo sobre la máquina objetivo; el descompresor del SO siempre está disponible. Menos código frágil que un Xpress Huffman hand-rolled, cero dependencias. |
| Module path | `github.com/telagem/agent-windows` | Placeholder ajustable con `go mod edit`. |

## 4. Estructura del proyecto

```
agent-windows/
├── go.mod
├── cmd/agent/main.go            # entrypoint: flags, elevación, orquestación, timeout global
├── internal/
│   ├── privilege/               # detección de elevación (UAC) + detección VM/sandbox
│   ├── collector/
│   │   ├── collector.go         # interface Collector, Artifact, Priority
│   │   ├── runner.go            # ejecuta por prioridad, aísla panics, timeout por colector
│   │   ├── prefetch/
│   │   ├── bam/
│   │   ├── shimcache/
│   │   └── amcache/
│   ├── winfs/                   # primitivas Windows de bajo nivel compartidas
│   │   ├── vss/                 # crear/montar/borrar snapshot VSS
│   │   ├── reghive/             # parser regf/hbin propio (regf → celdas → valores)
│   │   └── compression/         # wrapper RtlDecompressBufferEx (ntdll syscall)
│   ├── report/                  # Report, Finding, hash-chain, firma Ed25519
│   ├── transport/               # Uploader (interfaz) + cliente HTTP del contrato
│   └── consent/                 # gate de consentimiento (CLI por ahora)
└── testdata/                    # muestras binarias reales para tests de parsers
```

**Aislamiento de fallos:** un colector que falla registra un `Finding` categoría `INFO` (colector caído) y **no** tumba el escaneo. El `runner` recupera panics por colector.

## 5. Interfaces núcleo (Fase 1)

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]Artifact, error)
    Priority() int // menor = antes; volátiles primero
}

type Artifact struct {
    Type      string          // "prefetch", "bam", ...
    Source    string          // path/hive de origen
    Data      json.RawMessage // payload estructurado del artefacto
    Collected time.Time
}
```

El `runner` ordena por `Priority()`, corre cada colector con su propio contexto derivado del timeout global, y recupera panics traduciéndolos a `Finding` INFO.

## 6. Reporte, cadena de custodia y firma (Fase 1)

Structs exactamente como el spec:

```go
type Report struct {
    SessionID    string
    Platform     string        // "windows"
    AgentVersion string
    StartedAt    time.Time
    EndedAt      time.Time
    ConsentAt    time.Time
    Machine      MachineInfo   // OS, build, uptime, elevación, VM
    Findings     []Finding
    HashChain    []string
    Signature    string
    Status       string        // COMPLETE | ABORTED | ERROR
}

type Finding struct {
    ID         string
    Category   string    // ANTI_FORENSIC | EXECUTION | PERSISTENCE | EMULATOR | KNOWN_CHEAT
    Severity   string    // INFO | LOW | MEDIUM | HIGH | CRITICAL
    Confidence float64
    Title      string
    Evidence   string    // artefacto crudo que lo respalda
    Artifact   string    // de dónde salió
    Timestamp  *time.Time
}
```

**Flujo de firma:**
1. Al iniciar, el agente genera un par **Ed25519 efímero**.
2. Pide `nonce` de sesión al servidor. Si está offline → nonce local y `Status` marca `unverified_nonce`.
3. Cada `Finding` se serializa canónicamente (JSON con claves ordenadas), se hashea SHA-256 y se **encadena**: `H_n = SHA256(H_{n-1} || hash(finding_n))`. `H_0` incorpora el nonce de sesión.
4. Los findings se suben en **streaming** conforme se generan (no al final).
5. Al cerrar, se firma `H_root` con la clave privada; se sube el reporte final con la pubkey.
6. Si el proceso muere a mitad → el servidor ya tiene el stream → sesión `ABORTED`. En una telagem eso pesa casi tanto como un hallazgo positivo.

## 7. Contrato cliente-servidor

Interfaz `Uploader` en el agente; el server la implementa como HTTP + JSON.

| Paso | Método | Endpoint | Body | Respuesta |
|---|---|---|---|---|
| Abrir sesión | `POST` | `/api/v1/sessions` | `{agentVersion, pubkey, consentAt, machineInfoHash}` | `{sessionId, nonce}` |
| Stream de findings | `POST` | `/api/v1/sessions/:id/findings` | `{seq, finding, chainHash}` (uno o batch) | `202` |
| Cerrar sesión | `POST` | `/api/v1/sessions/:id/complete` | `{report, signature, hashRoot}` | `{verifyUrl}` |
| Heartbeat | `POST` | `/api/v1/sessions/:id/heartbeat` | `{seq}` | `200` |

- Reintentos con **backoff exponencial (máx 3 intentos)**.
- IDs de hardware **hasheados** antes de salir del equipo: SHA-256 con el nonce como salt → no correlacionable entre sesiones. Nunca se envían crudos.
- Si `/sessions` no responde, el agente sigue en modo local-first y deja el reporte listo para reintento manual.
- El servidor valida firma, nonce y continuidad de la cadena, y emite una **URL pública de verificación**.

## 8. Colectores de ejecución (Fase 2)

Primitivas compartidas construidas primero:
- `winfs/vss` — crea un snapshot de volumen, lo monta, devuelve un path de solo lectura, lo destruye al cerrar.
- `winfs/reghive` — parser del formato **regf/hbin**: cabecera regf → bins → celdas (`nk`, `vk`, `sk`, listas), navegación por claves y lectura de valores. Ve entradas presentes en el hive aunque la API viva no las muestre.
- `winfs/compression` — wrapper de `RtlDecompressBufferEx` (ntdll) por syscall, para bloques Xpress Huffman (MAM).

| Colector | Técnica | Extrae |
|---|---|---|
| **Prefetch** | Lee `C:\Windows\Prefetch\*.pf`; si empieza con `MAM\x04` descomprime vía ntdll; parsea header por versión v23/v26/v30/v31 | nombre del ejecutable, hash del path, run count, últimos 8 timestamps de ejecución, volúmenes referenciados, archivos cargados |
| **BAM** | Parser regf sobre hive `SYSTEM` desde snapshot VSS: `CurrentControlSet\Services\bam\State\UserSettings\{SID}` | path completo + timestamp de última ejecución, por usuario (SID) |
| **ShimCache** | Parser regf → valor binario `AppCompatCache` en `Session Manager\AppCompatCache` → parsea el formato binario según versión de Windows | path + mtime de ejecutables vistos por el sistema |
| **AmCache** | Parser regf sobre `Amcache.hve` (copiado desde VSS) | **SHA-1** de ejecutables, path, timestamps (el hash sobrevive al borrado del archivo) |

Todos emiten `Artifact` con `Data` estructurado. **Ningún colector correlaciona todavía** — eso es fase 4. Solo recolectan fielmente.

## 9. Consentimiento (mínimo para fases 1–2)

Antes de recolectar nada, el gate `consent` (CLI por ahora) lista en lenguaje claro exactamente qué se va a recolectar y registra el timestamp del consentimiento en el reporte. **Nunca** se recolecta contenido de archivos personales, credenciales, historial ni mensajes: solo metadatos forenses (nombres, hashes, timestamps, paths). Buena parte de la comunidad es menor de edad → identificadores de hardware hasheados antes de salir del equipo.

## 10. Estrategia de testing

- **Parsers = la parte frágil → tests con muestras binarias reales** en `testdata/`: un `.pf` de cada versión (v23/v26/v30/v31, comprimido y sin comprimir), y fragmentos de hive con entradas BAM/ShimCache/AmCache conocidas. Tests table-driven que verifican campos exactos.
- `winfs/compression`: test round-trip contra un blob MAM real.
- `report`: test de que la cadena de hashes es determinista y que alterar cualquier finding rompe la verificación de firma.
- `transport`: test contra un `httptest.Server` que simula el contrato completo (incluye caso server caído → local-first).
- `winfs/vss`, `privilege`: dependen del SO; se aíslan detrás de interfaces mockeables. Los tests unitarios cubren la lógica; la integración real con VSS/UAC se prueba a mano.

## 11. Orden de implementación (para la fase de plan)

1. `go.mod` + esqueleto `cmd/agent/main.go` + interfaz `Collector` + `runner` con aislamiento de panics.
2. `privilege` (elevación + VM).
3. `report` (Ed25519, hash-chain) + `transport` (Uploader + cliente HTTP + local-first).
4. `consent` CLI.
5. `winfs/compression` (RtlDecompressBufferEx) + tests.
6. `winfs/reghive` (parser regf) + tests.
7. `winfs/vss` (snapshot).
8. Colectores: Prefetch → BAM → ShimCache → AmCache, cada uno con sus tests.

## 12. Manejo de falsos positivos (preparado, se explota en fase 4)

Cada `Finding` lleva `Confidence`. En fases 1–2 los colectores capturan el contexto necesario para que la fase 4 distinga: fecha de instalación de Windows, SSD con prefetch deshabilitado legítimamente, huecos por antivirus/actualizaciones. Los hallazgos de baja confianza se presentarán como contexto, no como acusación.
