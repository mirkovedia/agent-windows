//go:build windows

// cmd/agent/main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/telagem/agent-windows/internal/agent"
	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/consent"
	"github.com/telagem/agent-windows/internal/elevate"
	"github.com/telagem/agent-windows/internal/privilege"
	"github.com/telagem/agent-windows/internal/report"
	"github.com/telagem/agent-windows/internal/transport"
	"github.com/telagem/agent-windows/internal/ui"
	"github.com/telagem/agent-windows/internal/verdict"
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

// attachParentConsole engancha el proceso a la consola desde la que se lo
// invocó, si existe.
//
// El binario se compila con -H windowsgui para que el doble clic NO abra una
// ventana negra detrás de la interfaz. El costo es que el proceso deja de
// tener consola propia, así que el modo -console quedaría mudo al correrlo
// desde una terminal. Esto lo recupera: si hay consola padre, se adjunta y se
// reabren los descriptores estándar sobre ella; si no hay (doble clic), no
// hace nada y el flujo gráfico sigue igual.
func attachParentConsole() {
	const attachParentProcess = 0xFFFFFFFF // (DWORD)-1

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")
	if r, _, _ := attach.Call(uintptr(attachParentProcess)); r == 0 {
		return // no había consola padre: se ejecutó con doble clic
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
}

// machineInfo arma el estado de la máquina que va al reporte. Lo comparten el
// modo consola y el modo interfaz.
func machineInfo(elevated bool) report.MachineInfo {
	vm := privilege.DetectVM()
	return report.MachineInfo{
		OS:            runtime.GOOS,
		UptimeMinutes: uptimeMinutes(),
		Elevated:      elevated,
		VM:            vm.Detected,
		VMReasons:     vm.Reasons,
	}
}

// defaultReportPath deja el reporte junto al ejecutable. Es lo que permite que
// la app sea útil con doble clic, sin que el usuario tenga que pasar
// argumentos ni saber qué es un flag.
func defaultReportPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "reporte.json"
	}
	return filepath.Join(filepath.Dir(exe), "reporte.json")
}

func main() {
	// WebView2 exige que la interfaz viva siempre en el mismo hilo del SO, y
	// Go puede mover una goroutine entre hilos en cualquier momento.
	runtime.LockOSThread()

	consoleMode := flag.Bool("console", false, "usar el modo consola en vez de la interfaz gráfica")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout global del escaneo")
	serverURL := flag.String("server", "", "URL base del servidor de verificación")
	outPath := flag.String("out", "", "ruta donde escribir el reporte (por defecto: junto al .exe)")
	flag.Parse()

	// Recuperar la salida por texto si el agente se invocó desde una terminal.
	attachParentConsole()

	elevated, err := privilege.IsElevated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo verificar la elevación: %v\n", err)
		os.Exit(2)
	}
	if !elevated {
		// Relanzarse pidiendo UAC en vez de rendirse con un mensaje que el
		// usuario probablemente ni llegue a leer: la ventana de consola se
		// cierra con el proceso.
		if err := elevate.Relaunch(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: el agente requiere privilegios de administrador.\n"+
				"No se pudo solicitar la elevación: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0) // la instancia elevada toma el control
	}

	if *consoleMode {
		runConsole(*timeout, *serverURL, *outPath, elevated)
		return
	}
	if err := runGUI(*timeout, *outPath, elevated); err != nil {
		// Sin WebView2 no se puede fallar en silencio: se explica qué pasó y
		// cómo seguir igual.
		fmt.Fprintf(os.Stderr, "No se pudo abrir la interfaz gráfica: %v\n\n"+
			"Es probable que falte el runtime de WebView2. Se instala desde\n"+
			"https://developer.microsoft.com/microsoft-edge/webview2/\n"+
			"o podés correr el agente en modo consola:\n"+
			"    mirkkkov.exe -console\n", err)
		os.Exit(1)
	}
}

// runGUI abre la ventana y lanza el escaneo cuando el usuario acepta el
// consentimiento desde la interfaz.
func runGUI(timeout time.Duration, outPath string, elevated bool) error {
	if outPath == "" {
		outPath = defaultReportPath()
	}
	return ui.Run(ui.Options{
		Title: "Mirkkkov",
		OnScan: func(emit func(ui.Event)) {
			opts := agent.Options{
				Timeout: timeout,
				Version: agentVersion,
				Machine: machineInfo(elevated),
				Observer: collector.Observer{
					OnStart: func(i, total int, name string) {
						emit(ui.Event{
							Kind:  ui.KindCollectorStart,
							Index: i, Total: total, Collector: name,
						})
					},
					OnFinish: func(i, total int, res collector.Result) {
						// Mostrar los hallazgos notables apenas se descubren,
						// antes de que termine el escaneo completo.
						streamFindings(res, emit)

						ev := ui.Event{
							Kind:  ui.KindCollectorDone,
							Index: i, Total: total,
							Collector: res.Collector,
							Artifacts: len(res.Artifacts),
						}
						if res.Err != nil {
							ev.Error = res.Err.Error()
						}
						emit(ev)
					},
				},
			}
			rep, err := agent.RunLive(context.Background(), opts, transport.NewLocalUploader(outPath))
			if err != nil {
				emit(ui.Event{Kind: ui.KindScanError, Error: err.Error()})
				return
			}
			emit(ui.Event{Kind: ui.KindScanDone, Report: &rep})
		},
	})
}

// maxLiveFindingsPerCollector acota cuántos hallazgos se empujan a la vista en
// vivo por colector. El USN puede traer miles de artefactos; pasada cierta
// cantidad la lista deja de ser información y pasa a ser ruido, además de
// castigar al render.
const maxLiveFindingsPerCollector = 150

// streamFindings empuja a la interfaz los hallazgos notables de un colector
// apenas termina, sin esperar al escaneo completo.
//
// La severidad que se muestra es preliminar (ver verdict.Preview): los combos
// y la deduplicación se aplican recién al final, así que un hallazgo puede
// aparecer acá como HIGH y terminar como CRITICAL en la pantalla final.
func streamFindings(res collector.Result, emit func(ui.Event)) {
	if res.Err != nil {
		return
	}
	shown := 0
	for _, a := range res.Artifacts {
		if shown >= maxLiveFindingsPerCollector {
			return
		}
		p := verdict.Preview(a)
		if !p.Notable {
			continue
		}
		shown++
		emit(ui.Event{
			Kind:      ui.KindFinding,
			Severity:  p.Severity,
			Category:  p.Category,
			Title:     p.Title,
			Path:      a.Source,
			Collector: res.Collector,
		})
	}
}

// runConsole conserva el flujo original: consentimiento por stdin y salida por
// texto. Sigue siendo el camino cuando no hay interfaz disponible.
func runConsole(timeout time.Duration, serverURL, outPath string, elevated bool) {
	if serverURL == "" && outPath == "" {
		outPath = defaultReportPath()
	}

	vm := privilege.DetectVM()
	if vm.Detected {
		fmt.Fprintf(os.Stderr, "AVISO: entorno de VM detectado (%v). El escaneo continúa.\n", vm.Reasons)
	}

	accepted, _, err := consent.Prompt(os.Stdin, os.Stdout)
	if errors.Is(err, consent.ErrNoInput) {
		fmt.Fprintln(os.Stderr, "\nERROR: no se pudo leer tu respuesta. Abrí una consola como "+
			"administrador y ejecutá el agente desde ahí.")
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
	if serverURL != "" {
		up = transport.NewHTTPUploader(serverURL, nil)
	} else {
		up = transport.NewLocalUploader(outPath)
	}

	opts := agent.Options{
		Timeout:   timeout,
		ServerURL: serverURL,
		Version:   agentVersion,
		Machine:   machineInfo(elevated),
	}

	rep, err := agent.RunLive(context.Background(), opts, up)
	if err != nil {
		fmt.Fprintf(os.Stderr, "el escaneo terminó con error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Escaneo %s: %d hallazgos, estado %s\n", rep.SessionID, len(rep.Findings), rep.Status)
	fmt.Printf("Veredicto: %s — %s\n", rep.Verdict.Level, rep.Verdict.Summary)
	if outPath != "" {
		fmt.Printf("Reporte escrito en %s\n", outPath)
	}
}
