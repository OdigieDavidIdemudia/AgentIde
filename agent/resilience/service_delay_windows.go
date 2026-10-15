//go:build windows

package resilience

import (
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// queryServiceRestartDelay reads the SCM recovery configuration and returns
// the delay before the first ServiceRestart action.
//
// The point is to bound the "no heartbeat for N" heuristic using the service's
// real configuration instead of a hardcoded guess. A service the installer
// configured to restart after 5 seconds and one configured for 60 seconds have
// very different plausible gaps, and treating them the same produced both false
// positives and, more importantly, missed the fast restarts that an EDR kill
// actually causes.
//
// Returns 0 when the configuration cannot be read, which makes the caller fall
// back to the conservative default.
func queryServiceRestartDelay() time.Duration {
	m, err := mgr.Connect()
	if err != nil {
		return 0
	}
	defer m.Disconnect()

	svc, err := m.OpenService(serviceName)
	if err != nil {
		return 0
	}
	defer svc.Close()

	actions, err := svc.RecoveryActions()
	if err != nil || len(actions) == 0 {
		return 0
	}

	// The first restart action is the one that will actually fire first.
	for _, a := range actions {
		if a.Type == windows.SC_ACTION_RESTART {
			return a.Delay
		}
	}
	return 0
}
