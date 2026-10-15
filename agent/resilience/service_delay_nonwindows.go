//go:build !windows

package resilience

import "time"

// There is no Service Control Manager on other platforms, so the restart bound
// cannot be derived from configuration and the caller falls back to the
// conservative default.
func queryServiceRestartDelay() time.Duration { return 0 }
