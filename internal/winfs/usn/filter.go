package usn

// relevantReasonMask agrega las razones USN forensicamente significativas.
const relevantReasonMask = ReasonDataOverwrite | ReasonDataTruncation |
	ReasonFileCreate | ReasonFileDelete | ReasonRenameOldName | ReasonRenameNewName

// reasonIsRelevant reporta si la máscara de razones incluye alguna relevante.
func reasonIsRelevant(reason uint32) bool {
	return reason&relevantReasonMask != 0
}
