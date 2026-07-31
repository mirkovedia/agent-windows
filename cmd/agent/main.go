//go:build windows

// cmd/agent/main.go
package main

import (
	"context"
	"errors"
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
	outPath := flag.String("out", "", "ruta donde escribir el reporte localmente (modo sin servidor)")
	flag.Parse()

	if *serverURL == "" && *outPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: indicá -server <url> para subir el reporte, o -out <archivo.json> "+
			"para guardarlo localmente. Sin ninguno de los dos el escaneo no tiene dónde entregar el resultado.")
		os.Exit(2)
	}

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

	accepted, _, err := consent.Prompt(os.Stdin, os.Stdout)
	if errors.Is(err, consent.ErrNoInput) {
		fmt.Fprintln(os.Stderr, "\nERROR: no se pudo leer tu respuesta. Esto pasa al abrir el .exe "+
			"desde el Explorador. Abrí primero una consola como administrador y ejecutá el agente desde ahí.")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR al pedir consentimiento: %v\n", err)
		os.Exit(2)
	}
	if !accepted {
		fmt.Fprintln(os.Stderr, "Escaneo cancelado: no se otorgó consentimiento.")
		os.Exit(1)
	}

	var up transport.Uploader
	if *serverURL != "" {
		up = transport.NewHTTPUploader(*serverURL, nil)
	} else {
		up = transport.NewLocalUploader(*outPath)
	}
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
	if *outPath != "" {
		fmt.Printf("Reporte escrito en %s\n", *outPath)
	}
}
