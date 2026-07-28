//go:build !windows

package vss

// Create no está soportado fuera de Windows.
func Create(volume string) (Snapshot, error) { return nil, ErrUnsupported }
