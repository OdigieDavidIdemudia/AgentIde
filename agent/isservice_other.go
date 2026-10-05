//go:build !windows

package main

// isWindowsService always reports false on non-Windows platforms.
func isWindowsService() (bool, error) {
	return false, nil
}
