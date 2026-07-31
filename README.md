# mirkkkov-pc

Agente forense por consentimiento para verificación anticheat en la comunidad de
Free Fire. Análisis forense post-hoc: reconstruye qué se ejecutó y qué se borró
en la máquina, con el jugador presente y previa aceptación explícita.

## Build

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-H windowsgui" -o mirkkkov.exe ./cmd/agent
```

El flag `-H windowsgui` evita que el doble clic abra una ventana de consola
detrás de la interfaz. El modo consola sigue funcionando: el agente se engancha
a la terminal desde la que se lo invocó.

## Ejecución

**Doble clic en `mirkkkov.exe`.** Nada más.

El agente pide elevación por UAC solo, abre su propia ventana, muestra qué
revisa y qué no, y espera tu consentimiento explícito antes de tocar nada.
Durante el escaneo vas viendo el avance de cada fuente, y al final el veredicto
con los hallazgos agrupados por categoría.

El reporte queda como `reporte.json` junto al ejecutable.

### Modo consola

Para automatizar o cuando no hay interfaz disponible:

```
mirkkkov.exe -console                                    # reporte junto al .exe
mirkkkov.exe -console -out reporte.json -timeout 10m     # ruta explícita
mirkkkov.exe -console -server https://<servidor>          # contra un servidor
```

El reporte local conserva la cadena de hash y la firma, pero **no está
verificado por un tercero**: no equivale a la evidencia de una sesión validada
contra el servidor.

## Privacidad

El agente recolecta **solo metadatos forenses** (nombres, hashes, timestamps,
paths). Nunca contenido de archivos, credenciales, historial ni mensajes. Los
identificadores de hardware se anonimizan antes de salir del equipo. El código
es público y el binario se compila de forma reproducible vía GitHub Actions.
