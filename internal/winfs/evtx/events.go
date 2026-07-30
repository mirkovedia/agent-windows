package evtx

import (
	"strconv"

	"github.com/telagem/agent-windows/internal/winfs/wintext"
)

// fieldSpec describe qué nombre y cómo interpretar cada substitution por
// posición (índice en subs, donde subs[0] es el EventID).
type fieldSpec struct {
	index int
	name  string
}

var eventFields = map[uint16][]fieldSpec{
	4624: {{1, "TargetUserName"}, {2, "LogonType"}},
	4634: {{1, "TargetUserName"}},
	1102: {{1, "SubjectUserName"}},
	104:  {{1, "Channel"}, {2, "SubjectUserName"}},
	7045: {{1, "ServiceName"}, {2, "ImagePath"}},
	106:  {{1, "TaskName"}},
	140:  {{1, "TaskName"}},
	141:  {{1, "TaskName"}},
}

// fieldsFor traduce las substitutions posicionales a un mapa nombre->valor
// según el EventID. Un índice fuera de rango se omite sin fallar.
func fieldsFor(eventID uint16, subs []SubValue) map[string]string {
	specs, ok := eventFields[eventID]
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		if s.index >= len(subs) {
			continue
		}
		out[s.name] = renderValue(subs[s.index])
	}
	return out
}

// renderValue convierte un SubValue a string legible según su tipo.
func renderValue(v SubValue) string {
	switch v.Type {
	case TypeString:
		return wintext.DecodeUTF16(v.Raw)
	case TypeUInt16:
		if len(v.Raw) >= 2 {
			return strconv.FormatUint(uint64(v.Raw[0])|uint64(v.Raw[1])<<8, 10)
		}
	case TypeUInt32:
		if len(v.Raw) >= 4 {
			return strconv.FormatUint(uint64(readU32(v.Raw, 0)), 10)
		}
	}
	return ""
}
