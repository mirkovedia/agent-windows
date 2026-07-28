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
