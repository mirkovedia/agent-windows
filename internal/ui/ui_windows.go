//go:build windows

package ui

import (
	"sync"

	webview "github.com/jchv/go-webview2"
)

// Run abre la ventana y bloquea hasta que el usuario la cierra.
//
// Debe llamarse desde el hilo principal con runtime.LockOSThread() activo:
// WebView2 exige que la interfaz viva siempre en el mismo hilo del sistema
// operativo, y Go puede mover una goroutine entre hilos en cualquier momento.
func Run(opts Options) error {
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  opts.Title,
			Width:  1100,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		return ErrWebViewUnavailable
	}
	defer w.Destroy()

	// emit serializa el evento y lo empuja a JS en el hilo de UI. El escaneo
	// corre en una goroutine, así que toda llamada a Eval tiene que pasar por
	// Dispatch; saltearse esto produce cuelgues difíciles de diagnosticar.
	emit := func(e Event) {
		payload, err := e.JSON()
		if err != nil {
			return
		}
		w.Dispatch(func() {
			w.Eval("window.onAgentEvent(" + payload + ")")
		})
	}

	var once sync.Once
	if err := w.Bind("startScan", func() {
		// once evita que un doble clic dispare dos escaneos concurrentes
		// sobre el mismo volumen.
		once.Do(func() {
			if opts.OnScan != nil {
				go opts.OnScan(emit)
			}
		})
	}); err != nil {
		return err
	}
	if err := w.Bind("closeApp", func() {
		w.Terminate()
	}); err != nil {
		return err
	}
	// revealPath abre el explorador en la ubicación del artefacto. Es lo que
	// permite pasar del hallazgo al archivo sin copiar rutas a mano.
	if err := w.Bind("revealPath", func(path string) bool {
		return Reveal(path) == nil
	}); err != nil {
		return err
	}

	w.SetHtml(Page())
	w.Run()
	return nil
}
