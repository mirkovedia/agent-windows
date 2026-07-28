package usn

import "testing"

func TestReasonIsRelevant(t *testing.T) {
	if !reasonIsRelevant(ReasonFileDelete) {
		t.Error("FileDelete debería ser relevante")
	}
	if reasonIsRelevant(0x80000000) { // USN_REASON_CLOSE, no relevante por sí solo
		t.Error("CLOSE-solo no debería ser relevante")
	}
}
