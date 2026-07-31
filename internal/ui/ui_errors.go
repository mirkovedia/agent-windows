package ui

import "errors"

// ErrWebViewUnavailable indica que no se pudo crear la ventana, casi siempre
// porque falta el runtime de WebView2. El llamador debe degradar a consola con
// un mensaje claro: un escaneo que no arranca es peor que uno feo.
var ErrWebViewUnavailable = errors.New("no se pudo iniciar WebView2")

// Options configura la ventana.
type Options struct {
	Title string
	// OnScan se ejecuta en una goroutine cuando el usuario acepta el
	// consentimiento. emit ya viene envuelta en Dispatch, así que es seguro
	// llamarla desde cualquier goroutine.
	OnScan func(emit func(Event))
}
