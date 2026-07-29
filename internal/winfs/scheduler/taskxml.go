// internal/winfs/scheduler/taskxml.go
package scheduler

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// TaskDefinition es una tarea programada parseada desde su XML.
type TaskDefinition struct {
	RelPath   string // ruta relativa bajo Tasks\, ej. "Microsoft\Windows\Foo\Bar"
	Command   string // <Actions><Exec><Command>
	Arguments string // <Actions><Exec><Arguments>
	Hidden    bool   // <Settings><Hidden>
	Author    string // <RegistrationInfo><Author>
}

// taskXML mapea los campos forenses relevantes del XML de definición de
// tarea. Sin namespace explícito en los tags: encoding/xml empareja por
// nombre local e ignora el namespace por defecto, y el XML real usa un
// namespace fijo de Microsoft que no aporta nada distinguir aquí.
type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Settings struct {
		Hidden bool `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// ParseTaskXML decodifica un archivo de definición de tarea (UTF-16 con BOM,
// o UTF-8) y extrae los campos forenses relevantes.
func ParseTaskXML(raw []byte, relPath string) (TaskDefinition, error) {
	content := decodeXMLBytes(raw)
	dec := xml.NewDecoder(strings.NewReader(content))
	// El contenido ya está en UTF-8 (se decodificó arriba a mano); este
	// CharsetReader es un passthrough que solo evita que encoding/xml aborte
	// al ver la declaración <?xml encoding="UTF-16"?> que trae todo XML de
	// tarea real de Windows. No requiere ninguna dependencia externa.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var t taskXML
	if err := dec.Decode(&t); err != nil {
		return TaskDefinition{}, fmt.Errorf("parseo XML de tarea: %w", err)
	}
	return TaskDefinition{
		RelPath:   relPath,
		Command:   t.Actions.Exec.Command,
		Arguments: t.Actions.Exec.Arguments,
		Hidden:    t.Settings.Hidden,
		Author:    t.RegistrationInfo.Author,
	}, nil
}

// decodeXMLBytes detecta un BOM UTF-16LE (0xFF 0xFE) al inicio del buffer y
// lo decodifica a UTF-8; si no hay BOM, asume que ya es UTF-8/ASCII.
func decodeXMLBytes(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		return wintext.DecodeUTF16(raw[2:])
	}
	return string(raw)
}
