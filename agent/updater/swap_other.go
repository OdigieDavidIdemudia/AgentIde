//go:build !windows

package updater

import (
	"fmt"

	"agentide/core"
)

// swapAndRestart is only implemented on Windows for now.
func swapAndRestart(exePath, newPath string, logger *core.Logger) error {
	return fmt.Errorf("agent auto-update is only implemented on Windows")
}
