//go:build !windows

package core

import "os"

// Single-instance enforcement is Windows-only: the named-mutex primitive that
// provides it does not exist here, and on Linux the service manager already
// guarantees one instance.

// AcquireSingleInstance always succeeds off Windows.
func AcquireSingleInstance() (bool, error) { return true, nil }

// ExitIfAnotherInstance is a no-op off Windows.
func ExitIfAnotherInstance() { _ = os.Getpid() }
