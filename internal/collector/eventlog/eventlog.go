package eventlog

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/telagem/agent-windows/internal/collector"
	"github.com/telagem/agent-windows/internal/winfs/evtx"
	"github.com/telagem/agent-windows/internal/winfs/reghive"
	winscheduler "github.com/telagem/agent-windows/internal/winfs/scheduler"
	winservices "github.com/telagem/agent-windows/internal/winfs/services"
)

// Collector recolecta y correlaciona Event Logs (.evtx).
type Collector struct {
	SecurityPath  string
	SystemPath    string
	TaskSchedPath string
	SystemHive    string
	SoftwareHive  string
}

func New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector {
	return &Collector{
		SecurityPath:  securityPath,
		SystemPath:    systemPath,
		TaskSchedPath: taskSchedPath,
		SystemHive:    systemHive,
		SoftwareHive:  softwareHive,
	}
}

func (c *Collector) Name() string  { return "eventlog" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	arts := make([]collector.Artifact, 0)

	// Parsear los tres logs; un log ilegible no aborta los demás.
	secLog := c.openLog(c.SecurityPath, "Security", &arts)
	sysLog := c.openLog(c.SystemPath, "System", &arts)
	taskLog := c.openLog(c.TaskSchedPath, "TaskScheduler", &arts)

	logsCleared := false

	for _, log := range []*evtx.Log{secLog, sysLog, taskLog} {
		if log == nil {
			continue
		}
		for _, ts := range log.Tamper {
			arts = appendJSON(arts, "eventlog.tamper_signal", ts.Kind, ts)
		}
		for _, r := range log.Records {
			// Un .evtx real puede traer cientos de miles de records: se
			// respeta el timeout global igual que el resto de colectores.
			select {
			case <-ctx.Done():
				return arts, ctx.Err()
			default:
			}
			switch r.EventID {
			case 4624, 4634, 6005, 6006, 6008:
				arts = appendJSON(arts, "eventlog.session_timeline", r.Channel, timelineEntry(r))
			case 1102, 104:
				logsCleared = true
				arts = appendJSON(arts, "eventlog.log_cleared", r.Channel, clearEntry(r))
			}
		}
	}

	installs := collectInstalls(sysLog)
	taskEvents := collectTaskEvents(taskLog)
	curServices := c.currentNonStandardServices()
	curTasks := c.currentNonStandardTasks()

	for _, d := range CrossCheck(installs, curServices, taskEvents, curTasks, logsCleared) {
		arts = appendJSON(arts, "eventlog.desync", d.Subject, d)
	}
	return arts, nil
}

// openLog abre un .evtx; si falla, emite un artifact de error y devuelve nil.
func (c *Collector) openLog(path, channel string, arts *[]collector.Artifact) *evtx.Log {
	if path == "" {
		return nil
	}
	log, err := evtx.Open(path, channel)
	if err != nil {
		*arts = appendJSON(*arts, "eventlog.tamper_signal", channel,
			evtx.TamperSignal{Kind: "log_unreadable", Detail: err.Error()})
		return nil
	}
	return log
}

type timeline struct {
	Time    time.Time `json:"time"`
	EventID uint16    `json:"event_id"`
	User    string    `json:"user,omitempty"`
	Logon   string    `json:"logon_type,omitempty"`
}

func timelineEntry(r evtx.Record) timeline {
	return timeline{Time: r.Timestamp, EventID: r.EventID, User: r.Fields["TargetUserName"], Logon: r.Fields["LogonType"]}
}

type clear struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	By      string    `json:"cleared_by,omitempty"`
}

func clearEntry(r evtx.Record) clear {
	return clear{Time: r.Timestamp, Channel: r.Fields["Channel"], By: r.Fields["SubjectUserName"]}
}

func collectInstalls(log *evtx.Log) []InstallEvent {
	if log == nil {
		return nil
	}
	var out []InstallEvent
	for _, r := range log.Records {
		if r.EventID == 7045 {
			out = append(out, InstallEvent{ServiceName: r.Fields["ServiceName"], ImagePath: r.Fields["ImagePath"]})
		}
	}
	return out
}

func collectTaskEvents(log *evtx.Log) []TaskEvent {
	if log == nil {
		return nil
	}
	var out []TaskEvent
	for _, r := range log.Records {
		var action string
		switch r.EventID {
		case 106:
			action = "register"
		case 140:
			action = "update"
		case 141:
			action = "delete"
		default:
			continue
		}
		out = append(out, TaskEvent{Action: action, TaskName: r.Fields["TaskName"]})
	}
	return out
}

// currentNonStandardServices lee el hive SYSTEM y filtra a drivers no
// Microsoft. Si el hive no está disponible devuelve nil (la correlación de
// servicios se omite, pero el resto del colector sigue).
func (c *Collector) currentNonStandardServices() []winservices.DriverService {
	if c.SystemHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SystemHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		if root, err = h.OpenKey(`ControlSet002\Services`); err != nil {
			return nil
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil
	}
	var out []winservices.DriverService
	for _, s := range all {
		if winservices.IsNonMicrosoftDriver(s) {
			out = append(out, s)
		}
	}
	return out
}

// currentNonStandardTasks lee TaskCache\Tree del hive SOFTWARE y filtra las
// tareas fuera de la carpeta Microsoft\ (las del sistema generan ruido).
func (c *Collector) currentNonStandardTasks() []winscheduler.CachedTask {
	if c.SoftwareHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SoftwareHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	tree, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`)
	if err != nil {
		return nil
	}
	all, err := winscheduler.WalkTaskCacheTree(tree)
	if err != nil {
		return nil
	}
	var out []winscheduler.CachedTask
	for _, t := range all {
		if !strings.HasPrefix(t.RelPath, `Microsoft\`) {
			out = append(out, t)
		}
	}
	return out
}

func appendJSON(arts []collector.Artifact, typ, source string, v any) []collector.Artifact {
	b, _ := json.Marshal(v)
	return append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: time.Now()})
}
