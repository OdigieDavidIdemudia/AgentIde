//go:build windows

package core

import (
	"encoding/json"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// StatusPipeName is the named pipe the tray companion app connects to in
// order to learn what the agent is doing.
//
// The tray is a separate process from the agent service, so the agent has to
// publish status for it. Without this the tray had nothing to read and showed
// "Disconnected" permanently, regardless of whether the agent was healthy.
const StatusPipeName = `\\.\pipe\agentide`

// Status is the payload published to the tray. Deliberately small and stable:
// the tray renders these fields and nothing else.
type Status struct {
	// State is one of "disconnected", "connecting", "connected",
	// "assessing", "updating", "error".
	State string `json:"state"`
	// Message is a short human-readable elaboration shown in the tooltip.
	Message string `json:"message,omitempty"`
	// Version is the running agent's version string.
	Version string `json:"version,omitempty"`
	// Hostname identifies this endpoint.
	Hostname string `json:"hostname,omitempty"`
	// DashboardURL is the dashboard the agent reports to.
	DashboardURL string `json:"dashboard_url,omitempty"`
	// Since is when the agent entered this state (RFC3339).
	Since string `json:"since,omitempty"`
	// AssessmentActive reports whether a run is in progress.
	AssessmentActive bool `json:"assessment_active"`
	// PID lets the tray tell a restarted agent from the old one.
	PID int `json:"pid"`
}

var (
	statusMu      sync.Mutex
	currentStatus = Status{State: "disconnected"}
)

// SetStatus updates the status the tray will read. Safe from any goroutine.
func SetStatus(state, message string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	currentStatus.State = state
	currentStatus.Message = message
	currentStatus.Since = time.Now().Format(time.RFC3339)
	switch state {
	case "assessing":
		currentStatus.AssessmentActive = true
	case "connected", "connecting", "disconnected", "error":
		currentStatus.AssessmentActive = false
	}
}

// InitStatus seeds the status with details known at startup so the tray can
// show them before the first transition.
func InitStatus(version, hostname, dashboardURL string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	currentStatus.Version = version
	currentStatus.Hostname = hostname
	currentStatus.DashboardURL = dashboardURL
	currentStatus.PID = int(windows.GetCurrentProcessId())
	if currentStatus.State == "" {
		currentStatus.State = "disconnected"
	}
}

// GetStatus returns a copy of the current status.
func GetStatus() Status {
	statusMu.Lock()
	defer statusMu.Unlock()
	return currentStatus
}

// StartStatusPipe serves the current status to any tray process that connects.
//
// The protocol is deliberately trivial: one JSON status object per connection,
// then the pipe closes. The tray reconnects in its own loop, which keeps the
// agent free of per-client bookkeeping and lets the tray be restarted at any
// time without the agent noticing.
func StartStatusPipe(stop <-chan struct{}) {
	go func() {
		path, err := windows.UTF16PtrFromString(StatusPipeName)
		if err != nil {
			return
		}

		for {
			select {
			case <-stop:
				return
			default:
			}

			h, err := windows.CreateNamedPipe(
				path,
				windows.PIPE_ACCESS_DUPLEX,
				windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
				windows.PIPE_UNLIMITED_INSTANCES,
				4096, 4096, 0, nil,
			)
			if err != nil {
				// Another agent instance already owns the pipe. Back off
				// rather than spinning on it.
				select {
				case <-stop:
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}

			connected := make(chan struct{})
			go func() {
				defer close(connected)
				_ = windows.ConnectNamedPipe(h, nil)
			}()

			select {
			case <-stop:
				windows.CloseHandle(h)
				return
			case <-connected:
			}

			writeStatus(h)

			windows.DisconnectNamedPipe(h)
			windows.CloseHandle(h)
		}
	}()
}

func writeStatus(h windows.Handle) {
	payload, err := json.Marshal(GetStatus())
	if err != nil {
		return
	}
	// Terminate with a newline so a line-oriented reader gets a clean frame.
	payload = append(payload, '\n')
	var n uint32
	var ov windows.Overlapped
	windows.WriteFile(h, payload, &n, &ov)
}
