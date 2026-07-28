package wintime

import "time"

// FiletimeToTime convierte un FILETIME de Windows (intervalos de 100ns desde
// 1601-01-01 UTC) a time.Time UTC. Un valor cero devuelve time.Time{} (cero).
func FiletimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600 // segundos entre 1601 y 1970
	secs := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}
