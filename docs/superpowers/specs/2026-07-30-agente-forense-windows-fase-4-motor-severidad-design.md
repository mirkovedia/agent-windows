# Agente Forense Windows — Fase 4: Motor de Severidad y Veredicto (Design)

**Fecha:** 2026-07-30
**Estado:** Aprobado, listo para plan de implementación
**Depende de:** Fases 1–3D (11 colectores, `collector.Result`, `report.Finding`, `fsforensic`)

## Contexto

Tras las Fases 1–3D el agente recolecta evidencia de 11 colectores y **no concluye nada**. En
[`agent.go:90`](../../../internal/agent/agent.go) `resultToFindings` marca *todo* como
`Severity: "INFO"`, `Confidence: 0.0`, `Category: "EXECUTION"`. El comentario de esa función ya
anticipaba esta fase: *"la correlación real es fase 4"*.

El campo `Severity` de `report.Finding` declara soportar `INFO | LOW | MEDIUM | HIGH | CRITICAL`,
pero nada en el código emite otra cosa que `INFO`.

En la práctica esto significa que un moderador recibe una lista plana donde **un driver kernel
corriendo desde `Temp` pesa exactamente lo mismo que un prefetch de `notepad.exe`**, y donde el
volumen de evidencia neutra (unos 1000 archivos en `C:\Windows\Prefetch`, más el journal USN)
entierra las pocas señales que importan.

## Objetivo

Convertir artefactos crudos en hallazgos priorizados y un veredicto global auditable:

1. Asignar **categoría, severidad y confianza** a cada artefacto según su tipo y su contenido.
2. **Colapsar la evidencia neutra** en hallazgos de resumen, emitiendo individualmente solo lo
   que dispara alguna regla.
3. **Combinar señales** que juntas significan más que por separado.
4. Emitir un **veredicto global** que nunca afirme "limpio" sobre un escaneo degradado.

## Invariantes heredados

- Target `GOOS=windows GOARCH=amd64`, sin CGO. El motor es Go puro y **no** lleva build tag:
  corre y se testea en cualquier host.
- Runtime solo stdlib + `golang.org/x/sys`. Esta fase no necesita `x/sys`.
- Un colector que falla nunca tumba el escaneo.
- Código en inglés; comentarios y commits en español.

## Principio rector: el motor no acusa, prioriza

Este agente corre **con consentimiento** sobre la máquina de un jugador real, y su salida puede
usarse para sancionarlo. Por eso el motor se diseña con sesgo explícito hacia el falso negativo:

- La severidad alta se reserva a señales que **no ocurren por accidente** (backdating imposible,
  borrado del log de seguridad, CRC de `.evtx` roto).
- Todo hallazgo conserva su evidencia cruda, para que un humano pueda contradecir al motor.
- El veredicto `LIMPIO` **no se emite** si el escaneo estuvo degradado (ver "Veredicto global").

## Arquitectura

```
internal/verdict/            NUEVO: motor puro, sin I/O, sin build tags
  rules.go        tabla de regla base por tipo de artefacto + orden de severidad
  escalate.go     escalado por contenido (marcadores fsforensic) y por detalle del artefacto
  summarize.go    colapso de evidencia neutra en hallazgos de resumen
  correlate.go    combos de co-ocurrencia + extracción de tiempo por tipo
  verdict.go      Evaluate (entrada pública) + veredicto global
```

La entrada pública es una **función pura**:

```go
func Evaluate(results []collector.Result) ([]report.Finding, report.Verdict)
```

Toma exactamente lo que ya devuelve `collector.Run` y reemplaza a `resultToFindings` en
`runWithCollectors`. **El resto del flujo no se toca**: cadena de hash, firma y upload siguen
operando sobre los findings resultantes. Como `Evaluate` es pura, el set completo de reglas se
testea con `collector.Result` sintéticos — sin Windows, sin hives, sin `.evtx`.

### Cambios en `report`

```go
// Verdict es la conclusión global del escaneo.
type Verdict struct {
    Level            string   `json:"level"`   // LIMPIO | SOSPECHOSO | EVIDENCIA_FUERTE | INCOMPLETO
    Summary          string   `json:"summary"` // una línea en lenguaje llano
    Reasons          []string `json:"reasons,omitempty"`
    FailedCollectors []string `json:"failedCollectors,omitempty"`
}
```

`Report` gana `Verdict Verdict \`json:"verdict"\``. `Finding` no cambia de forma: empieza a usar
`Severity`/`Confidence`/`Category`, que ya existen.

## Reglas base por tipo de artefacto

Los 14 tipos que producen los colectores se dividen en dos grupos.

### Señales fuertes (bajo volumen)

| Tipo | Categoría | Severidad | Confianza | Fundamento |
|------|-----------|-----------|-----------|------------|
| `eventlog.log_cleared` | ANTI_FORENSIC | HIGH | 0.9 | Borrar el log de seguridad requiere intención y privilegio |
| `mft_timestomp` | ANTI_FORENSIC | HIGH | 0.8 | `SI.Created` anterior a `FN.Created` es imposible naturalmente |
| `eventlog.tamper_signal` | ANTI_FORENSIC | HIGH | 0.7 | CRC roto o salto de record-id: el `.evtx` fue editado a nivel binario |
| `eventlog.desync` | ANTI_FORENSIC | MEDIUM | 0.6 | Logs y registro no coinciden |
| `scheduled_task_desync` | ANTI_FORENSIC | ver escalado | ver escalado | Depende de la dirección de la desincronía |
| `service_driver` | PERSISTENCE | MEDIUM | 0.5 | Driver fuera de `System32\drivers` |
| `scheduled_task` | PERSISTENCE | MEDIUM | 0.5 | Tarea oculta o de nombre sospechoso |
| `deleted_entry` | ANTI_FORENSIC | LOW | 0.3 | Borrar archivos es normal; el nombre decide |

### Evidencia neutra (alto volumen)

`prefetch`, `bam`, `shimcache`, `amcache`, `usn`, `eventlog.session_timeline` → categoría
`EXECUTION`, severidad `INFO`, confianza `0.0`. No son sospechosas por sí mismas: son el registro
normal de una computadora en uso.

Un tipo desconocido (colector futuro sin regla) cae en `EXECUTION`/`INFO`/`0.0` y se cuenta como
neutro. El motor nunca falla por un tipo que no conoce.

## Escalado

### Por contenido

Si el `Source` del artefacto (ruta o nombre) matchea `fsforensic.IsSuspiciousName` — los
marcadores ya usados por USN y MFT: `cheat`, `inject`, `loader`, `bypass`, `aimbot`, `macro`,
`esp`, `hook`, `wipe`, `ccleaner`, `bleachbit` — la severidad **sube dos niveles, con tope en
HIGH**, y la confianza pasa a `0.8`.

El tope importa: `CRITICAL` queda reservado para los combos. Un nombre sospechoso es una señal
fuerte, pero por sí sola no es la afirmación más grave que el motor puede hacer — un archivo
puede llamarse `cheat_notes.txt` sin que nadie haya tramposeado.

Esto es lo que separa un `deleted_entry` cualquiera (LOW, ruido normal) de
`aimbot_loader.exe` borrado (HIGH). Y es lo que rescata de la evidencia neutra los pocos
artefactos que importan: un `prefetch` de `notepad.exe` se colapsa en el resumen, pero uno de
`injector.exe` se emite como hallazgo `EXECUTION` propio con severidad MEDIUM.

### Por detalle del artefacto

`scheduled_task_desync` tiene dos direcciones con peso muy distinto, distinguidas por su campo
`Kind`:

- `hive_only` → **HIGH**, confianza 0.8. El XML de la tarea fue borrado del disco pero la entrada
  sigue en `TaskCache`: alguien borró el archivo visible y no pudo limpiar el registro.
- `file_only` → **LOW**, confianza 0.3. El XML existe sin entrada en el registro; puede ser una
  tarea recién creada (condición de carrera legítima).

## Colapso de evidencia neutra

Por cada colector que produjo artefactos neutros se emite **un** hallazgo de resumen:

```
Categoría: EXECUTION   Severidad: INFO   Confianza: 0.0
Título:    "Evidencia de ejecución: prefetch"
Evidencia: "1247 artefactos registrados, 3 emitidos individualmente por coincidir con patrones sospechosos"
```

Los artefactos neutros que **sí** disparan escalado por contenido se emiten individualmente
además de contarse en el resumen. Los que no, quedan solo en el conteo.

Esto reduce un reporte de miles de entradas a unas decenas legibles, sin perder la trazabilidad
de lo que el motor decidió no destacar: el resumen dice cuántos hubo.

## Combos

Tres reglas de co-ocurrencia dentro del mismo escaneo. Deliberadamente pocas: cada combo es una
afirmación fuerte y su falso positivo es caro.

1. **Cluster anti-forense** — dos o más señales `ANTI_FORENSIC` de **tipos distintos** con
   severidad ≥ MEDIUM → el hallazgo de mayor severidad del cluster sube a **CRITICAL**.
   Fundamento: borrar logs *y* timestompear *y* editar el `.evtx` es un patrón deliberado; una
   sola de esas cosas puede tener explicación inocente.

2. **Persistencia sin rastro** — un `service_driver` o `scheduled_task` presente **y** un
   `eventlog.log_cleared` en el mismo escaneo → el hallazgo de persistencia sube a **CRITICAL**.
   Fundamento: hay algo instalado y el registro de cuándo se instaló desapareció.

3. **Amplificador temporal** — si dos señales que disparan un combo tienen ambas timestamp
   utilizable y caen dentro de **30 minutos**, se suma `+0.1` de confianza (tope 1.0).

### Límite explícito sobre el tiempo

No todos los artefactos traen fecha utilizable. Del análisis de las estructuras reales:

| Tipo | Campo de tiempo |
|------|-----------------|
| `mft_timestomp` | `SI.Created` |
| `deleted_entry` | `SI.Created` |
| `usn` | `Timestamp` |
| `eventlog.session_timeline` | `time` |
| `eventlog.log_cleared` | `time` |
| `service_driver` | **ninguno** (el registro no expone fecha en la struct) |
| `scheduled_task`, `scheduled_task_desync` | **ninguno** |
| `eventlog.tamper_signal`, `eventlog.desync` | **ninguno** |

Por eso los combos se definen sobre **co-ocurrencia en el escaneo**, y el tiempo actúa solo como
amplificador cuando ambos lados lo tienen. Prometer "correlación temporal" a secas sería vender
algo que los datos no sostienen. `Artifact.Collected` **no** sirve: es cuándo se recolectó, no
cuándo ocurrió el hecho.

## Veredicto global

Se calcula sobre los findings ya evaluados:

- **EVIDENCIA_FUERTE** — al menos un `CRITICAL`, o dos o más `HIGH` de categorías distintas.
- **SOSPECHOSO** — al menos un `HIGH`, o dos o más `MEDIUM`.
- **LIMPIO** — nada por encima de `LOW`.

Y una condición que se aplica **después** de las anteriores:

> Si algún colector falló, el nivel `LIMPIO` se convierte en **INCOMPLETO**.

Un escaneo donde el MFT no se pudo leer no vio la mitad de la evidencia; reportarlo como "limpio"
sería afirmar algo que el agente no sabe. Los niveles `SOSPECHOSO` y `EVIDENCIA_FUERTE` **no** se
degradan: la evidencia encontrada sigue siendo evidencia encontrada, pero `FailedCollectors`
queda poblado en ambos casos para que el lector lo pondere.

`Summary` es una línea en lenguaje llano ("2 señales anti-forenses y 1 mecanismo de persistencia
detectados") y `Reasons` enumera los títulos de los hallazgos que determinaron el nivel.

## Manejo de errores

- **Colector caído** — sigue emitiendo su hallazgo `INFO` de `ANTI_FORENSIC` (comportamiento
  actual), y además su nombre entra en `Verdict.FailedCollectors`.
- **`Data` que no parsea** — el escalado por detalle y la extracción de tiempo se saltan
  silenciosamente para ese artefacto; la regla base se aplica igual. Un JSON corrupto degrada la
  precisión, nunca tumba la evaluación.
- **Tipo desconocido** — regla neutra por defecto (ver arriba).
- `Evaluate` no devuelve error: siempre produce findings y veredicto. Es una función total.

## Testing

Todo se testea con `collector.Result` sintéticos construidos a mano — sin Windows, sin
privilegios, sin fixtures binarias.

| Archivo | Cobertura |
|---------|-----------|
| `rules_test.go` | Regla base por cada tipo conocido; tipo desconocido → neutro; orden de severidad |
| `escalate_test.go` | Nombre sospechoso sube un nivel y fija confianza 0.8; `hive_only` → HIGH y `file_only` → LOW; `Data` corrupta no rompe |
| `summarize_test.go` | N artefactos neutros → 1 resumen con el conteo correcto; los sospechosos se emiten aparte y siguen contados |
| `correlate_test.go` | Dos ANTI_FORENSIC distintos → CRITICAL; un solo tipo repetido **no** dispara el cluster; persistencia + log_cleared → CRITICAL; amplificador dentro y fuera de la ventana |
| `verdict_test.go` | Cada umbral de nivel; **LIMPIO + colector caído → INCOMPLETO**; SOSPECHOSO con colector caído sigue SOSPECHOSO pero lista el fallo |
| `agent_test.go` (existente) | Sigue verde: el reemplazo de `resultToFindings` no altera el contrato de `runWithCollectors` |

## Fuera de alcance

- Firmas de cheats conocidos por hash (`KNOWN_CHEAT` queda declarado en `Category` pero ningún
  artefacto lo produce todavía; necesita una base de firmas, que es su propia fase).
- Detección de emuladores (`EMULATOR`, misma situación).
- Umbrales configurables por archivo: las reglas viven en código y se cambian con un release.
  Exponerlas como configuración invitaría a que cada organizador afloje los umbrales hasta que
  el agente diga lo que quiere oír.
- Puntaje numérico agregado: se descartó deliberadamente para no habilitar baneos automáticos por
  umbral.
