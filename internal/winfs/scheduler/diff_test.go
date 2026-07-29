// internal/winfs/scheduler/diff_test.go
package scheduler

import "testing"

func TestDiffTasksNoDesync(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `Foo\Bar`}}
	cached := []CachedTask{{RelPath: `Foo\Bar`, ID: "{GUID}"}}
	got := DiffTasks(onDisk, cached)
	if len(got) != 0 {
		t.Fatalf("DiffTasks = %+v, want empty", got)
	}
}

func TestDiffTasksHiveOnly(t *testing.T) {
	cached := []CachedTask{{RelPath: `Foo\Ghost`, ID: "{GUID-1}"}}
	got := DiffTasks(nil, cached)
	if len(got) != 1 || got[0].Kind != HiveOnly || got[0].TaskCacheID != "{GUID-1}" || got[0].RelPath != `Foo\Ghost` {
		t.Fatalf("DiffTasks = %+v", got)
	}
}

func TestDiffTasksFileOnly(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `Foo\Orphan`}}
	got := DiffTasks(onDisk, nil)
	if len(got) != 1 || got[0].Kind != FileOnly || got[0].RelPath != `Foo\Orphan` {
		t.Fatalf("DiffTasks = %+v", got)
	}
}

func TestDiffTasksMixed(t *testing.T) {
	onDisk := []TaskDefinition{{RelPath: `A`}, {RelPath: `B`}}
	cached := []CachedTask{{RelPath: `A`, ID: "{A}"}, {RelPath: `C`, ID: "{C}"}}
	got := DiffTasks(onDisk, cached)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2: %+v", len(got), got)
	}
}
