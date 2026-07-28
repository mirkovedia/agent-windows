package mft

import "time"

// stompTolerance absorbe diferencias menores de resolución al comparar timestamps.
const stompTolerance = time.Second

// Verdict es el resultado de evaluar timestomping sobre un registro.
type Verdict struct {
	Stomped      bool
	Reasons      []string
	SubSecZeroed bool // heurística de confianza; no gatilla por sí sola
}

// detectTimestomp compara SI vs FN. Marca backdating imposible naturalmente:
// SI.Created (o SI.Modified) anterior a FN.Created, que es cuando se creó la
// entrada de nombre. Los ceros (timestamps ausentes) no gatillan.
func detectTimestomp(si, fn Timestamps) Verdict {
	var v Verdict
	if isBefore(si.Created, fn.Created) {
		v.Stomped = true
		v.Reasons = append(v.Reasons, "SI.Created anterior a FN.Created")
	}
	if isBefore(si.Modified, fn.Created) {
		v.Stomped = true
		v.Reasons = append(v.Reasons, "SI.Modified anterior a FN.Created")
	}
	if subSecZeroed(si.Created) || subSecZeroed(si.Modified) {
		v.SubSecZeroed = true
	}
	return v
}

// isBefore reporta si a precede a b por más de la tolerancia. Ignora ceros.
func isBefore(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	return a.Add(stompTolerance).Before(b)
}

// subSecZeroed reporta si t no es cero pero su parte sub-segundo es exactamente
// 0 — típico de tiempos seteados por API (los naturales tienen resolución 100ns).
func subSecZeroed(t time.Time) bool {
	return !t.IsZero() && t.Nanosecond() == 0
}
