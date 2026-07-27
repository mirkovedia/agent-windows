package privilege

import "golang.org/x/sys/windows"

// IsElevated reporta si el proceso actual corre con token elevado (UAC).
func IsElevated() (bool, error) {
	var token windows.Token
	proc := windows.CurrentProcess()
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}
