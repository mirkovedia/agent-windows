// internal/collector/scheduler/scheduler_test.go
package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/telagem/agent-windows/internal/collector"
)

func TestCollectorMetadata(t *testing.T) {
	c := New(`C:\Windows\System32\Tasks`, `C:\Windows\System32\config\SOFTWARE`)
	if c.Name() != "scheduled_tasks" {
		t.Fatalf("Name = %q, want scheduled_tasks", c.Name())
	}
	if c.Priority() != collector.PriorityDisk {
		t.Fatalf("Priority = %d, want %d", c.Priority(), collector.PriorityDisk)
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ collector.Collector = New(`C:\Windows\System32\Tasks`, `C:\Windows\System32\config\SOFTWARE`)
}

// TestCollectWithSyntheticTasksDir valida el flujo completo sobre un
// directorio temporal con dos tareas: una oculta (debe reportarse) y una
// normal sin nada sospechoso (no debe reportarse). El hive SOFTWARE no
// existe en este test -> el cross-check se omite sin abortar el colector.
func TestCollectWithSyntheticTasksDir(t *testing.T) {
	dir := t.TempDir()
	hiddenXML := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>true</Hidden></Settings>
  <Actions><Exec><Command>C:\Temp\hidden.exe</Command></Exec></Actions>
</Task>`
	normalXML := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>false</Hidden></Settings>
  <Actions><Exec><Command>C:\Program Files\App\updater.exe</Command></Exec></Actions>
</Task>`
	if err := os.WriteFile(filepath.Join(dir, "HiddenTask"), []byte(hiddenXML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "NormalTask"), []byte(normalXML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := New(dir, filepath.Join(dir, "no-existe.hve"))
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var sawHidden bool
	for _, a := range arts {
		if a.Type == "scheduled_task" {
			sawHidden = true
			if a.Source != "HiddenTask" {
				t.Errorf("Source = %q, want HiddenTask (la tarea normal no debería reportarse)", a.Source)
			}
		}
		if a.Type == "scheduled_task_desync" {
			t.Errorf("no se esperaba desync sin hive SOFTWARE: %+v", a)
		}
	}
	if !sawHidden {
		t.Fatal("esperaba un artifact scheduled_task para la tarea oculta")
	}
}
