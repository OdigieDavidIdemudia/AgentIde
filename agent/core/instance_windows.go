//go:build windows

package core

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Single-instance enforcement.
//
// Enterprise agents are strictly one process per host. Nothing in the agent
// enforced that, and it showed: the AgentIde service, the AgentIdeGuard health
// monitor and a manually launched agent all ran simultaneously, competing for
// the same dashboard socket. The registry then flipped between them and the
// WebSocket livelock followed — each registration evicting the previous one's
// socket.
//
// A named mutex makes the second instance exit immediately instead of
// corrupting the session, which is the behaviour every managed agent relies on.
//
// Local\ is scoped to the session, which is correct here: the agent runs as a
// service in session 0 while a CLI invocation runs in the user session, and the
// two must not block each other.

const instanceMutexName = `Local\AgentIde.SingleInstance`

// AcquireSingleInstance takes the per-host agent mutex.
//
// Returns false when another instance already holds it. Callers should exit
// rather than continue — two agents reporting to one dashboard produce
// conflicting state, not redundancy.
func AcquireSingleInstance() (bool, error) {
	name, err := windows.UTF16PtrFromString(instanceMutexName)
	if err != nil {
		return false, fmt.Errorf("mutex name: %w", err)
	}

	// SECURITY_ATTRIBUTES left nil, so the mutex takes the default DACL.
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		// CreateMutex reports ERROR_ALREADY_EXISTS through the error, not only
		// through GetLastError — checking the latter would let a second instance
		// through every time.
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false, nil
		}
		return false, fmt.Errorf("create instance mutex: %w", err)
	}

	// Hold the handle for the process lifetime. Leaking it is deliberate: the
	// kernel closes it when the process exits, which is exactly the semantics
	// needed for a lock that tracks process liveness.
	_ = h
	return true, nil
}

// ExitIfAnotherInstance is a convenience wrapper for the normal startup path.
func ExitIfAnotherInstance() {
	ok, err := AcquireSingleInstance()
	if err != nil {
		// Never block startup on this: a mutex failure must not stop the agent
		// from reporting at all.
		fmt.Printf("[WARN] single-instance check failed, continuing: %v\n", err)
		return
	}
	if !ok {
		fmt.Fprintf(os.Stderr,
			"AgentIde is already running on this host (pid hint: mutex %s held).\n"+
				"Exiting to avoid a second instance reporting to the dashboard.\n",
			instanceMutexName)
		os.Exit(3)
	}
}
