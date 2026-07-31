package ui

import (
	"strings"
	"testing"
)

// TestPageInlinesAssets verifica que el HTML servido sea autocontenido: sin
// esto la ventana quedaría sin estilos ni lógica, porque SetHtml no resuelve
// referencias a archivos externos.
func TestPageInlinesAssets(t *testing.T) {
	page := Page()
	if !strings.Contains(page, "<style>") {
		t.Error("el CSS debe quedar embebido en una etiqueta <style>")
	}
	if !strings.Contains(page, "<script>") {
		t.Error("el JS debe quedar embebido en una etiqueta <script>")
	}
	if strings.Contains(page, "<!--INLINE_CSS-->") || strings.Contains(page, "<!--INLINE_JS-->") {
		t.Error("los marcadores deben quedar reemplazados")
	}
}

func TestPageHasTheThreeScreens(t *testing.T) {
	page := Page()
	for _, id := range []string{"screen-consent", "screen-scan", "screen-results"} {
		if !strings.Contains(page, id) {
			t.Errorf("falta la pantalla %q", id)
		}
	}
}

// TestPageExposesEventEntryPoint protege el contrato Go<->JS: el backend
// empuja eventos llamando a esta función global.
func TestPageExposesEventEntryPoint(t *testing.T) {
	if !strings.Contains(Page(), "onAgentEvent") {
		t.Error("la UI debe exponer window.onAgentEvent")
	}
}

// TestPageBindsBackendFunctions verifica que la UI llame a las funciones que
// Go expone con Bind. Si un nombre no coincide, el botón no hace nada y el
// fallo es silencioso.
func TestPageBindsBackendFunctions(t *testing.T) {
	page := Page()
	for _, fn := range []string{"window.startScan", "window.closeApp", "window.revealPath"} {
		if !strings.Contains(page, fn) {
			t.Errorf("la UI debe invocar %s", fn)
		}
	}
}

// TestPageHandlesEverySeverity garantiza que exista una clase CSS por cada
// severidad que el motor puede emitir.
func TestPageHandlesEverySeverity(t *testing.T) {
	page := Page()
	for _, cls := range []string{"sev-info", "sev-low", "sev-medium", "sev-high", "sev-critical"} {
		if !strings.Contains(page, cls) {
			t.Errorf("falta la clase de severidad %q", cls)
		}
	}
}

// TestPageHasLiveScanElements fija los elementos que el feed en vivo necesita.
// Si alguno se renombra, las detecciones dejarían de aparecer sin ningún error
// visible: el JS fallaría en silencio dentro del WebView.
func TestPageHasLiveScanElements(t *testing.T) {
	page := Page()
	for _, id := range []string{
		"live-feed",      // contenedor de detecciones en vivo
		"live-counters",  // contadores por severidad
		"collector-list", // lista de fuentes
		"statusbar",      // barra de progreso al pie
		"progress-bar",   // relleno de la barra
		"progress-pct",   // porcentaje
		"progress-count", // N / total
	} {
		if !strings.Contains(page, id) {
			t.Errorf("falta el elemento %q que usa la vista en vivo", id)
		}
	}
}

// TestPageHandlesFindingEvent verifica que la UI despache el evento de
// hallazgo en vivo, que es el que hace que las detecciones aparezcan mientras
// el escaneo corre.
func TestPageHandlesFindingEvent(t *testing.T) {
	if !strings.Contains(Page(), `case "finding"`) {
		t.Error("la UI debe manejar el evento finding")
	}
}

// TestPageHandlesEveryVerdictLevel hace lo mismo con los niveles de veredicto.
func TestPageHandlesEveryVerdictLevel(t *testing.T) {
	page := Page()
	for _, cls := range []string{"level-limpio", "level-incompleto", "level-sospechoso", "level-evidencia_fuerte"} {
		if !strings.Contains(page, cls) {
			t.Errorf("falta la clase de veredicto %q", cls)
		}
	}
}
