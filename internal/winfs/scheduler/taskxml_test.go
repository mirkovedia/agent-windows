// internal/winfs/scheduler/taskxml_test.go
package scheduler

import (
	"encoding/binary"
	"testing"
)

const sampleTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>DESKTOP-ABC\User</Author>
  </RegistrationInfo>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Temp\loader.exe</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>`

// utf16LEWithBOM codifica s como UTF-16LE con BOM inicial, igual que los XML
// de tareas que escribe el Task Scheduler real.
func utf16LEWithBOM(s string) []byte {
	buf := []byte{0xFF, 0xFE}
	for _, r := range s {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(r)) // el fixture no usa caracteres fuera del BMP
		buf = append(buf, b...)
	}
	return buf
}

func TestParseTaskXMLUTF16WithBOM(t *testing.T) {
	raw := utf16LEWithBOM(sampleTaskXML)
	got, err := ParseTaskXML(raw, `Microsoft\Windows\Foo\Bar`)
	if err != nil {
		t.Fatalf("ParseTaskXML: %v", err)
	}
	if got.Command != `C:\Temp\loader.exe` {
		t.Errorf("Command = %q", got.Command)
	}
	if got.Arguments != "-silent" {
		t.Errorf("Arguments = %q", got.Arguments)
	}
	if !got.Hidden {
		t.Error("Hidden = false, want true")
	}
	if got.Author != `DESKTOP-ABC\User` {
		t.Errorf("Author = %q", got.Author)
	}
	if got.RelPath != `Microsoft\Windows\Foo\Bar` {
		t.Errorf("RelPath = %q", got.RelPath)
	}
}

func TestParseTaskXMLPlainUTF8(t *testing.T) {
	got, err := ParseTaskXML([]byte(sampleTaskXML), `Foo\Bar`)
	if err != nil {
		t.Fatalf("ParseTaskXML: %v", err)
	}
	if got.Command != `C:\Temp\loader.exe` {
		t.Errorf("Command = %q", got.Command)
	}
}

func TestParseTaskXMLCorrupt(t *testing.T) {
	if _, err := ParseTaskXML([]byte("no es xml"), "x"); err == nil {
		t.Fatal("esperaba error con contenido corrupto")
	}
}
