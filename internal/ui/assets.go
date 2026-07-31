// internal/ui/assets.go
package ui

import (
	_ "embed"
	"strings"
)

//go:embed assets/index.html
var indexHTML string

//go:embed assets/app.css
var appCSS string

//go:embed assets/app.js
var appJS string

// Page devuelve el documento HTML completo, con el CSS y el JS embebidos.
// Se arma en memoria porque SetHtml no resuelve archivos externos: la página
// tiene que ser autocontenida o la ventana queda sin estilos ni lógica.
//
// Esta es también la razón por la que no se levanta un servidor HTTP local:
// una herramienta forense que abre un socket a la escucha es mucho más difícil
// de justificar ante un antivirus o ante un jugador desconfiado.
func Page() string {
	page := strings.Replace(indexHTML, "<!--INLINE_CSS-->", "<style>"+appCSS+"</style>", 1)
	page = strings.Replace(page, "<!--INLINE_JS-->", "<script>"+appJS+"</script>", 1)
	return page
}
