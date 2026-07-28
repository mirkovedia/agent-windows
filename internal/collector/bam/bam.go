// internal/collector/bam/bam.go
package bam

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
)

// Entry es una ejecución registrada por BAM (Background Activity Moderator).
type Entry struct {
	SID            string    `json:"sid"`
	ExecutablePath string    `json:"executablePath"`
	LastExecution  time.Time `json:"lastExecution"`
}

// Collector lee las entradas BAM del hive SYSTEM.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al hive SYSTEM dado (idealmente vía VSS).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath}
}

func (c *Collector) Name() string  { return "bam" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := readFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	entries, err := parseBAM(h)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "bam",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

// parseBAM recorre los SID bajo UserSettings y decodifica sus valores.
func parseBAM(h *reghive.Hive) ([]Entry, error) {
	base := `ControlSet001\Services\bam\State\UserSettings`
	root, err := h.OpenKey(base)
	if err != nil {
		// Algunos sistemas usan CurrentControlSet resuelto a ControlSet002.
		root, err = h.OpenKey(`ControlSet002\Services\bam\State\UserSettings`)
		if err != nil {
			return nil, err
		}
	}
	sidKeys, err := root.Subkeys()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, sidKey := range sidKeys {
		sid := sidKey.Name()
		values, err := sidKey.Values()
		if err != nil {
			continue
		}
		for path, raw := range values {
			ts, ok := decodeBAMValue(raw)
			if !ok {
				continue
			}
			entries = append(entries, Entry{SID: sid, ExecutablePath: path, LastExecution: ts})
		}
	}
	return entries, nil
}

// decodeBAMValue extrae el FILETIME de los primeros 8 bytes del valor BAM.
func decodeBAMValue(raw []byte) (time.Time, bool) {
	if len(raw) < 8 {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(raw[:8])
	if ft == 0 {
		return time.Time{}, false
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC(), true
}
