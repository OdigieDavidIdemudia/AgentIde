//go:build !windows

package core

// Status is the payload published to the tray. On non-Windows hosts there is
// no named pipe and no system tray, so these are inert no-ops kept so the
// agent compiles and any shared call sites stay portable.

type Status struct {
	State            string `json:"state"`
	Message          string `json:"message,omitempty"`
	Version          string `json:"version,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	DashboardURL     string `json:"dashboard_url,omitempty"`
	Since            string `json:"since,omitempty"`
	AssessmentActive bool   `json:"assessment_active"`
	PID              int    `json:"pid"`
}

func SetStatus(string, string)          {}
func InitStatus(string, string, string) {}
func GetStatus() Status                 { return Status{State: "unavailable"} }
func StartStatusPipe(<-chan struct{})   {}
