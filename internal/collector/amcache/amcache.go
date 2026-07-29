// internal/collector/amcache/amcache.go
package amcache

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// Entry es un ejecutable registrado por AmCache. El SHA-1 sobrevive al borrado
// del archivo, lo que lo hace crítico para el forense.
type Entry struct {
	SHA1     string    `json:"sha1"`
	Path     string    `json:"path"`
	LinkDate time.Time `json:"linkDate"`
}

// Collector lee InventoryApplicationFile del Amcache.hve.
type Collector struct {
	HivePath string
}

// New crea el colector apuntando al Amcache.hve dado (copiado vía VSS).
func New(amcacheHivePath string) *Collector {
	return &Collector{HivePath: amcacheHivePath}
}

func (c *Collector) Name() string  { return "amcache" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	entries, err := parseAmcache(h)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0, len(entries))
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "amcache",
			Source:    c.HivePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

// parseAmcache recorre InventoryApplicationFile extrayendo hash, path y fecha.
func parseAmcache(h *reghive.Hive) ([]Entry, error) {
	root, err := h.OpenKey(`Root\InventoryApplicationFile`)
	if err != nil {
		return nil, err
	}
	subs, err := root.Subkeys()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, s := range subs {
		vals, err := s.Values()
		if err != nil {
			continue
		}
		e := Entry{}
		if p, ok := vals["LowerCaseLongPath"]; ok {
			e.Path = wintext.DecodeUTF16(p)
		}
		if fid, ok := vals["FileId"]; ok {
			e.SHA1 = normalizeFileID(wintext.DecodeUTF16(fid))
		}
		if ld, ok := vals["LinkDate"]; ok {
			e.LinkDate = parseLinkDate(wintext.DecodeUTF16(ld))
		}
		if e.Path != "" || e.SHA1 != "" {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// normalizeFileID quita el prefijo "0000" que AmCache antepone al SHA-1.
// El FileId real es "0000" + SHA-1 (40 hex) = 44 chars; se acepta cualquier
// longitud con ese prefijo para no depender de la versión del hive.
func normalizeFileID(raw string) string {
	if len(raw) > 4 && strings.HasPrefix(raw, "0000") {
		return raw[4:]
	}
	return raw
}

// parseLinkDate parsea el LinkDate de AmCache ("MM/DD/YYYY HH:MM:SS").
func parseLinkDate(s string) time.Time {
	t, err := time.Parse("01/02/2006 15:04:05", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}
