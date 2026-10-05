// Package watchdog protects endpoints during EDR assessments.
//
// When a vendor's protection is disabled for an assessment, a detached
// watchdog process is spawned. If the agent process is killed (which is
// exactly what some EDRs do mid-test) or hangs, the watchdog re-enables
// the vendor automatically — the endpoint is never left unprotected.
package watchdog

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"agentide/disabler"
)

const childPollInterval = 5 * time.Second

// MarkerPath returns the watchdog marker file path for a vendor.
// The parent rewrites this file every few seconds as a heartbeat;
// the watchdog child restores the vendor if the heartbeat goes stale.
func MarkerPath(vendor string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, strings.ToLower(vendor))
	return filepath.Join(os.TempDir(), "agentide-watchdog-"+safe+".flag")
}

// Guard is the parent-side handle on an armed watchdog.
type Guard struct {
	vendor    string
	marker    string
	heartbeat time.Duration
	deadline  time.Time
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// Start arms the watchdog for a vendor that is about to be (or has just
// been) disabled. heartbeatTimeout is how long the child waits for a
// fresh heartbeat before considering the parent dead; maxDuration is the
// absolute deadline after which the vendor is re-enabled regardless.
func Start(vendor string, heartbeatTimeout, maxDuration time.Duration) (*Guard, error) {
	marker := MarkerPath(vendor)
	deadline := time.Now().Add(maxDuration)

	g := &Guard{
		vendor:    vendor,
		marker:    marker,
		heartbeat: heartbeatTimeout,
		deadline:  deadline,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}

	// Create the marker before spawning so the child has a live file to watch.
	if err := touch(marker); err != nil {
		return nil, err
	}

	args := []string{
		"-watchdog",
		vendor,
		marker,
		strconv.Itoa(int(heartbeatTimeout.Seconds())),
		strconv.FormatInt(deadline.Unix(), 10),
	}
	if err := spawnSelf(args); err != nil {
		_ = os.Remove(marker)
		return nil, err
	}

	go g.refreshLoop()
	return g, nil
}

// Stop halts the heartbeat and removes the marker, which makes the
// watchdog child exit quietly. Call after the vendor has been re-enabled.
func (g *Guard) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
	<-g.doneCh
	_ = os.Remove(g.marker)
}

// refreshLoop keeps the marker file fresh while the assessment runs.
func (g *Guard) refreshLoop() {
	defer close(g.doneCh)
	interval := g.heartbeat / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			_ = touch(g.marker)
		}
	}
}

func touch(path string) error {
	now := time.Now()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, _ = f.WriteString(now.Format(time.RFC3339))
	_ = f.Close()
	return os.Chtimes(path, now, now)
}

// watchdogDecision is what the watchdog child should do on a poll.
type watchdogDecision int

const (
	decisionContinue watchdogDecision = iota // keep monitoring
	decisionExit                             // parent finished normally
	decisionRestore                          // parent dead/stuck or deadline hit
)

// evaluate inspects the marker file and decides what the child
// should do. Returns the decision and, for stale heartbeats, the age.
func evaluate(marker string, heartbeatTimeout time.Duration, deadline time.Time) (watchdogDecision, time.Duration) {
	fi, err := os.Stat(marker)
	if os.IsNotExist(err) {
		return decisionExit, 0
	}
	if err == nil {
		if age := time.Since(fi.ModTime()); age > heartbeatTimeout {
			return decisionRestore, age
		}
	}
	if time.Now().After(deadline) {
		return decisionRestore, 0
	}
	return decisionContinue, 0
}

// RunChild is the watchdog process entrypoint (invoked via -watchdog).
// It blocks until the marker disappears (parent finished normally), the
// heartbeat goes stale (parent dead or hung), or the deadline passes —
// in the latter two cases the vendor is re-enabled before exiting.
func RunChild(vendor, marker string, heartbeatTimeout time.Duration, deadline time.Time) {
	logf, _ := os.OpenFile(
		filepath.Join(os.TempDir(), "agentide-watchdog.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644,
	)
	defer logf.Close()
	logln := func(format string, args ...interface{}) {
		fmt.Fprintf(logf, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}

	logln("watchdog armed: vendor=%s marker=%s heartbeat=%s deadline=%s",
		vendor, marker, heartbeatTimeout, deadline)

	for {
		decision, age := evaluate(marker, heartbeatTimeout, deadline)
		switch decision {
		case decisionExit:
			logln("marker removed — parent restored vendor, exiting")
			return
		case decisionRestore:
			if age > 0 {
				logln("heartbeat stale for %s (parent dead or hung) — re-enabling %s", age, vendor)
			} else {
				logln("deadline exceeded — re-enabling %s", vendor)
			}
			restore(vendor)
			return
		}

		time.Sleep(childPollInterval)
	}
}

func restore(vendor string) {
	if err := disabler.Enable(vendor); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog: failed to re-enable %s: %v\n", vendor, err)
	}
}
