# Agente Forense Windows — Fase 5: Calibración de Falsos Positivos (Design)

**Fecha:** 2026-07-31
**Estado:** Aprobado, listo para plan de implementación
**Depende de:** Fases 1–4 (11 colectores, motor de severidad `internal/verdict`)

## Contexto: la primera ejecución real

El 2026-07-31 se corrió el agente por primera vez sobre una máquina Windows real y limpia. El
resultado fue **inaceptable**:

```
1070 hallazgos
Veredicto: EVIDENCIA_FUERTE
  1 CRITICAL, 83 HIGH, 970 MEDIUM, 11 LOW, 5 INFO
```

`EVIDENCIA_FUERTE` es el nivel más grave que el motor puede emitir. En una verificación real ese
reporte habría sancionado a un jugador inocente. **La tasa de falsos positivos es efectivamente
del 100%: el agente acusa a cualquiera.**

Ninguna cantidad de tests sintéticos lo habría detectado, porque los fixtures se escribieron con
nombres como `aimbot_loader.exe`, no con `microsoft-windows-earlydownloader.manifest`.

### Evidencia recogida del reporte real

El único `CRITICAL` fue:

```
pyproject-hooks.rkyv     (caché del gestor de paquetes uv, de Python)
```

Matcheó el marcador `hook` dentro de "pyproject-**hook**s". El propio detector de timestomping
había concluido `"Stomped": false` — el archivo estaba intacto.

Los 83 `HIGH` fueron todos manifiestos de **WinSxS**, el almacén de componentes de Windows, que
Windows Update borra y reemplaza de forma rutinaria:

| Archivo legítimo | Marcador | Cómo matcheó |
|---|---|---|
| `...bios-loader.resources` | `loader` | token propio en el nombre |
| `...core-earlydownloader` | `loader` | "down**loader**" |
| `...moderninjectionbroker` | `inject` | "modern**inject**ionbroker" |
| `...manager-unenrollhook` | `hook` | "unenroll**hook**" |
| `...namespaceextension` | `esp` | "nam**esp**aceextension" |
| `...threatresponseengine` | `esp` | "r**esp**onseengine" |
| `...pagespaces-spaceutil` | `esp` | "pag**esp**aces" |

Los 970 `MEDIUM` se repartieron así:

| Cantidad | Título |
|---|---|
| 767 | `Artefacto usn` |
| 85 | `Los eventos no coinciden con el estado del sistema` |
| 60 | `Tarea programada oculta o sospechosa` |
| 56 | `Driver instalado fuera de la ruta estándar` |

Muestreando los USN aparecen los mismos dos patrones, más un tercero:

| Archivo legítimo | Marcador | Cómo matcheó |
|---|---|---|
| `logUploaderSettings.ini` | `loader` | "log**Uploader**Settings" |
| `gamingservicesproxy_11.dll` | `esp` | "gamingservic**esp**roxy" (cruza dos palabras) |

Y el mismo archivo aparece repetido decenas de veces: `gamingservicesproxy_11.dll` figura 10+
veces, `logUploaderSettings.ini` 5+. El USN journal registra **cada modificación** del archivo y
hoy cada evento se convierte en un hallazgo independiente.

## Causas raíz

1. **Matcheo por substring** en `fsforensic.IsSuspiciousName` (`strings.Contains`). El marcador
   `esp` matchea "r**esp**onse", "nam**esp**ace", "servic**es p**roxy". `loader` matchea
   "up**loader**" y "down**loader**". `hook` matchea cualquier proyecto Python o los `.git/hooks/`.
   Explica el `CRITICAL`, los 83 `HIGH` y la mayoría de los 767 USN — unos **851 de 1070**.
2. **Sin deduplicación**: N eventos USN sobre el mismo archivo producen N hallazgos.
3. **`task_no_register_log` ignora la rotación de logs.** Emite una desincronía por cada tarea
   cuyo evento de registro ya no está en el log, pero los Event Logs se reciclan: una tarea creada
   hace meses **nunca** va a tener su evento 106. Explica los 85.
4. **Filtro de tareas ocultas demasiado amplio.** Windows tiene decenas de tareas propias marcadas
   `Hidden`. Explica los 60.
5. **Heurística de drivers demasiado amplia.** 56 drivers fuera de `System32\drivers` en una
   máquina normal: antivirus, GPU, VPN, virtualización.

## Objetivo

Que el agente, ejecutado sobre una máquina limpia, emita veredicto **`LIMPIO`**, sin perder la
capacidad de detectar los artefactos que sí importan.

## Principio rector

El motor de Fase 4 está bien construido: hace exactamente lo que se diseñó. **El problema son las
señales de entrada.** Esta fase no rediseña el motor; corrige los detectores que lo alimentan.

Postura acordada para las señales que resultaron comunes en máquinas limpias: **se siguen
reportando, pero a nivel `INFO`**, de modo que quedan disponibles para un analista sin mover el
veredicto global. Se conserva la trazabilidad sin acusar.

## Arquitectura

Los arreglos tocan tres puntos y **ningún colector cambia su lógica de recolección**: los
colectores siguen juntando evidencia, el motor sigue siendo quien juzga.

```
internal/winfs/fsforensic/fsforensic.go   matcheo en dos niveles + detección de componentes MS
internal/verdict/escalate.go              reglas de detalle para desync, tareas y drivers
internal/verdict/verdict.go               deduplicación por (tipo, ruta)
```

Cambiar `fsforensic` tiene un efecto secundario deseado: los colectores `usn`, `deleted` y `mft`
lo usan como filtro de recolección, así que **dejan de recolectar** buena parte del ruido en
origen, no solo de clasificarlo.

## Componentes

### 1. Matcheo en dos niveles (`fsforensic`)

`IsSuspiciousName` pasa de `strings.Contains` sobre una lista plana a dos categorías:

```go
// strongMarkers: largos y sin ambigüedad. Ninguna palabra legítima los
// contiene, así que se siguen buscando como substring.
var strongMarkers = []string{"cheat", "aimbot", "ccleaner", "bleachbit"}

// weakMarkers: cortos o comunes como fragmento de palabras legítimas. Solo
// cuentan cuando aparecen como token completo del nombre.
var weakMarkers = []string{"inject", "injector", "loader", "bypass", "macro", "esp", "hook", "wipe"}

// tokenize parte un nombre en tokens por separadores (-, _, ., espacio) y por
// cambios de camelCase, en minúscula.
func tokenize(name string) []string
```

Se conserva el conjunto de 11 marcadores original y solo se reparte, con **una** excepción:
se agrega `injector` como variante de token de `inject`. Es necesaria, no un agregado de alcance:
el test existente exige que `FreeFire_Injector.exe` se detecte, y bajo matcheo de token exacto
`injector` ≠ `inject`. Enumerar la variante es preferible a relajar el matcheo a prefijo, porque
el prefijo reintroduciría el falso positivo de `pyproject-hooks` (`hooks` empieza con `hook`).

Verificación contra los nombres reales del reporte:

| Nombre real | Resultado |
|---|---|
| `logUploaderSettings.ini` | limpio — tokens `[log, uploader, settings, ini]`, `uploader` ≠ `loader` |
| `gamingservicesproxy_11.dll` | limpio — `esp` no es token |
| `pyproject-hooks.rkyv` | limpio — `hooks` ≠ `hook` |
| `aimbot_loader.exe` | detectado — `aimbot` es marcador fuerte |
| `aimbotloader.exe` | detectado — `aimbot` por substring, aunque no haya separadores |
| `esp.dll` | detectado — `esp` es token completo |
| `FreeFire_Injector.exe` | detectado — tokens `[free, fire, injector, exe]`, `injector` es marcador |

**Costo aceptado:** el matcheo exacto de token no cubre plurales ni derivados. Un cheat llamado
`hooks.dll` no se detecta por el marcador `hook`. Es una decisión deliberada: dado que los falsos
positivos resultaron ser el modo de falla dominante, se prefiere el falso negativo. Los
marcadores fuertes siguen cubriendo el caso sin separadores.

### 2. Componentes de Microsoft (`fsforensic`)

Los nombres de WinSxS sobreviven a la tokenización porque `loader` **sí** es un token propio en
`...bios-loader.resources`. Necesitan una regla aparte:

```go
// IsSystemComponent reporta si el nombre corresponde a un componente del
// almacén WinSxS de Windows. Se identifica por el token de clave pública de
// Microsoft (31bf3856ad364e35) o por los prefijos de arquitectura del
// almacén. Windows Update borra y reemplaza estos archivos de forma rutinaria.
func IsSystemComponent(name string) bool
```

Criterio: el nombre contiene `_31bf3856ad364e35_` (token de clave pública de Microsoft), **o**
empieza con `amd64_microsoft-`, `wow64_microsoft-`, `x86_microsoft-` o `msil_microsoft-`.

Se usa el patrón del **nombre** y no la ruta a propósito: en el reporte real muchas rutas salen
como `\<sin-resolver>\...` porque la reconstrucción del directorio padre falla, así que una
allowlist por ruta no los alcanzaría.

`IsSuspiciousName` devuelve `false` para cualquier componente de sistema, sin evaluar marcadores.

### 3. Deduplicación (`verdict`)

`Evaluate` colapsa hallazgos repetidos por la clave `(tipo de artefacto, Source)`. Se conserva el
primero y se anota la cantidad de ocurrencias en su evidencia:

```
"3 eventos sobre este artefacto"
```

Aplica a todos los tipos, no solo USN: cualquier colector que reporte el mismo objeto varias veces
se beneficia.

### 4. Reglas de detalle (`verdict/escalate.go`)

Tres reglas nuevas en `escalateByDetail`, todas bajando a `INFO` con confianza `0.0`:

- **`eventlog.desync` con `Kind == "task_no_register_log"`** → `INFO`. La regla no puede ser sana
  sin la fecha de creación de la tarea para compararla contra la ventana que cubre el log. Se
  sigue emitiendo para auditoría, con la limitación anotada.
- **`scheduled_task` con `RelPath` bajo `Microsoft\`** → `INFO`. Windows trae decenas de tareas
  propias marcadas como ocultas.
- **`service_driver` cuyo `ImagePath` cae en una ubicación normal de instalación** → `INFO`.
  Ubicaciones consideradas normales: `\program files\`, `\program files (x86)\`,
  `\windows\system32\driverstore\`. Un driver en `\temp\`, `\downloads\` o `\appdata\` conserva
  su `MEDIUM`.

Las otras direcciones de `eventlog.desync` (`service_no_install_log`, `service_installed_then_removed`,
`task_delete_desync`) **no** cambian: siguen en `MEDIUM`.

## Manejo de errores

Sin cambios respecto de Fase 4: `Evaluate` sigue siendo una función total. Un payload que no
parsea deja la regla base y no rompe la evaluación. `IsSuspiciousName` e `IsSystemComponent` son
puras sobre un string y no pueden fallar.

## Testing

Los tests se construyen con **los nombres reales que causaron los falsos positivos**, extraídos
del reporte del 2026-07-31. Un test que afirma *"`pyproject-hooks.rkyv` no debe escalar"* vale más
que cualquier fixture inventado, porque salió de una máquina real.

| Archivo | Cobertura |
|---|---|
| `fsforensic_test.go` | Cada nombre real del reporte → no sospechoso; `aimbot_loader.exe`, `aimbotloader.exe`, `esp.dll`, `cheat.exe` → sí; `tokenize` con separadores y camelCase; `IsSystemComponent` con los manifiestos reales y con nombres normales |
| `escalate_test.go` | `task_no_register_log` → INFO; otras direcciones de desync → MEDIUM; tarea oculta bajo `Microsoft\` → INFO y fuera de `Microsoft\` → MEDIUM; driver en `Program Files` → INFO y en `Temp` → MEDIUM |
| `verdict_test.go` | Tres artefactos con el mismo `(tipo, Source)` → un hallazgo con el conteo en la evidencia; artefactos distintos no se colapsan |

**Criterio de éxito de la fase:** re-ejecutar el escaneo sobre la misma máquina y obtener veredicto
`LIMPIO`.

## Segunda iteración: lo que reveló la re-ejecución

Aplicadas las correcciones anteriores, la segunda corrida bajó de 1070 a **306 hallazgos** (92
señales pasaron a `INFO`), pero el veredicto **siguió siendo `EVIDENCIA_FUERTE`**: 1 `CRITICAL` y
44 `HIGH`. Aparecieron tres causas nuevas, todas con la misma raíz conceptual:

> El agente estaba convirtiendo **"no pude verificar"** en **"hay evidencia"**.

### 6. Los marcadores débiles pesaban demasiado

El `CRITICAL` fue `run-hook.cmd`, un script de desarrollo (de nuevo con `"Stomped": false`). El
token exacto `hook` es correcto como match, pero es **evidencia floja**: no distingue un cheat de
cualquier script con hooks de build o de git.

**Corrección:** el escalado por nombre ahora tiene tope según el peso del marcador. Los fuertes
(`cheat`, `aimbot`, `ccleaner`, `bleachbit`) llegan a `HIGH`; los débiles (token exacto: `hook`,
`esp`, `loader`, `inject`, `macro`, `wipe`, `bypass`) topan en `MEDIUM`. Se agrega
`fsforensic.HasStrongMarker` para que el motor pueda distinguirlos.

### 7. Tareas ilegibles se reportaban como borradas (bug, no calibración)

Los 42 `HIGH` restantes eran `scheduled_task_desync` de tipo `hive_only`, **todos sobre tareas
propias de Windows** (`Microsoft\Windows\Application Experience\AitAgent`, `KernelCeipTask`,
`DirectXDatabaseUpdater`…).

Causa: en `collector/scheduler`, un XML que no se puede leer o parsear se descartaba del listado
en disco. Windows pone ACLs restrictivas sobre varias de sus propias tareas, así que el
cross-check contra `TaskCache` concluía que habían sido **borradas del disco**. Pero `WalkDir` ya
había probado que el archivo existe: solo no se pudo abrir.

**Corrección:** una tarea cuyo XML es ilegible o no parsea se registra igual como presente
(`TaskDefinition{RelPath: rel}`). Queda sin `Command`/`Hidden`, así que el filtro de tareas
reportables no la destaca, pero el diff deja de inventar un borrado. Una tarea realmente borrada
del disco sigue sin aparecer en `WalkDir`, así que la detección real no se debilita.

### 8. Señales de log que no prueban manipulación

Las 2 `HIGH` restantes eran `eventlog.tamper_signal`:

- **`log_unreadable`** sobre `Microsoft-Windows-TaskScheduler%4Operational.evtx`: el log **no
  existe** en la máquina. Windows lo trae deshabilitado por defecto. Se reportaba con el título
  *"Archivo de log alterado a nivel binario"*, que es directamente falso.
- **`dirty_flag`**: esperable en un snapshot VSS de un log que estaba abierto y escribiéndose.

**Corrección:** `eventlog.tamper_signal` se diferencia por `Kind`. `chunk_crc_invalid`,
`record_id_gap` y `truncated` se mantienen en `HIGH` (implican edición binaria real);
`log_unreadable`, `dirty_flag` y `full_flag` bajan a `INFO`. El título del tipo pasa a
*"Anomalía estructural en archivo de log"*, neutro y verdadero para todos los casos.

## Fuera de alcance

- **Resolución de rutas `<sin-resolver>`.** Muchos artefactos del MFT y del USN no logran
  reconstruir su directorio padre. Afecta la legibilidad del reporte, no la corrección de la
  severidad. Merece su propia investigación.
- **Verificación de firma Authenticode** de drivers, que resolvería la causa 5 de raíz en vez de
  por heurística de ruta. Requiere criptografía de certificados sin CGO; es una fase propia.
- Agregar marcadores de detección nuevos (`wallhack`, etc.): esta fase solo recalibra los que ya
  existen.
