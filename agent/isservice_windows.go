//go:build windows

package main

import winsvc "golang.org/x/sys/windows/svc"

// isWindowsService reports whether the process is running under the
// Windows Service Control Manager.
func isWindowsService() (bool, error) {
	return winsvc.IsWindowsService()
}
