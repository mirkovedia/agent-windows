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

Requiere privilegios de administrador. **Abrí primero una consola como
administrador** y ejecutá el agente desde ahí; no lo abras con doble clic ni con
clic derecho desde el Explorador, porque necesita argumentos y porque la ventana
se cierra al terminar el proceso, sin darte tiempo a leer el resultado.

Hay que indicar dónde entregar el reporte. Contra un servidor de verificación:

```
agent.exe -server https://<servidor-de-verificacion> -timeout 10m
```

O en modo local, sin servidor, escribiendo el reporte a un archivo:

```
agent.exe -out reporte.json -timeout 10m
```

El modo local sirve para inspeccionar qué detecta el agente. El reporte que
genera conserva la cadena de hash y la firma, pero **no está verificado por un
tercero**: no equivale a la evidencia de una sesión validada contra el servidor.

## Privacidad

El agente recolecta **solo metadatos forenses** (nombres, hashes, timestamps,
paths). Nunca contenido de archivos, credenciales, historial ni mensajes. Los
identificadores de hardware se anonimizan antes de salir del equipo. El código
es público y el binario se compila de forma reproducible vía GitHub Actions.
