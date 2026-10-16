// Command agentide-tray is the system tray companion for the AgentIde agent.
//
// Why this does not use github.com/lxn/walk
//
// It used to. walk fails at startup on Windows 10 build 19045 and later with
// "TTM_ADDTOOL failed": ToolTip.addTool builds a TOOLINFO without assigning
// LpszText, and TTM_ADDTOOL rejects a NULL text pointer on those builds.
// Every widget calls AddTool unconditionally (walk/widget.go), so this is not
// avoidable from the caller — no walk GUI can start on a current Windows host.
// The maintained fork has the identical defect.
//
// Rather than ship a tray that can never appear, the notification icon is built
// on systray, which is a maintained, purpose-built dependency for exactly this.
// The status window that walk provided is dropped; status is surfaced in the
// tray menu title and tooltip instead, which is where an operator looks for it
// anyway and costs no extra process surface.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// statusPipe is the named pipe the agent serves its status on. One JSON
	// object per connection; the tray polls.
	statusPipe = `\\.\pipe\agentide`

	serviceName    = "AgentIde"
	fallbackDash   = "https://localhost:8443"
	pollInterval   = 3 * time.Second
	pollTimeout    = 2 * time.Second
	serviceNameAlt = "AgentIdeGuard"

	// configCandidates are the paths the installer and service have used for
	// config.json, newest layout first.
	autostartValue = "AgentIde Tray"
	runKey         = `Software\Microsoft\Windows\CurrentVersion\Run`
)

// Populated by the build via -ldflags -X. Shown in the tooltip so an operator
// can tell which build is installed without opening the About-less file
// properties dialog. The agent's own version is shown separately in the menu,
// since that is the version which matters when correlating with the dashboard.
var (
	version   = "dev"
	buildDate = "unknown"
)

var (
	configCandidates = []string{
		filepath.Join(os.Getenv("ProgramFiles"), `AgentIde`, "config.json"),
		filepath.Join(os.Getenv("ProgramFiles"), `AgentIDE`, "config.json"),
		`C:\ProgramData\AgentIde\config.json`,
	}
	logCandidates = []string{
		filepath.Join(os.Getenv("ProgramFiles"), `AgentIde`, "agentide.log"),
		filepath.Join(os.Getenv("ProgramFiles"), `AgentIDE`, "agentide.log"),
		`C:\ProgramData\AgentIde\agentide.log`,
	}
)

// agentStatus mirrors the JSON the agent publishes over the pipe.
type agentStatus struct {
	State            string `json:"state"`
	Message          string `json:"message"`
	Version          string `json:"version"`
	Hostname         string `json:"hostname"`
	DashboardURL     string `json:"dashboard_url"`
	Since            string `json:"since"`
	AssessmentActive bool   `json:"assessment_active"`
	PID              int    `json:"pid"`
}

// label is the one-line summary shown in the tooltip and menu title.
func (s agentStatus) label() string {
	switch s.State {
	case "connected":
		if s.Message != "" {
			return s.Message
		}
		return "Connected"
	case "connecting":
		return "Connecting to dashboard"
	case "assessing":
		if s.Message != "" {
			return s.Message
		}
		return "Assessment in progress"
	case "disconnected":
		return "Disconnected from dashboard"
	case "error":
		if s.Message != "" {
			return s.Message
		}
		return "Error"
	default:
		return "Waiting for agent service"
	}
}

// stateDot is a block glyph rather than a smooth indicator, matching the
// dashboard's treatment.
func (s agentStatus) stateDot() string {
	switch s.State {
	case "connected":
		return "■"
	case "connecting", "assessing":
		return "◧"
	default:
		return "□"
	}
}

func main() {
	systray.Run(onReady, onExit)
}

func onReady() {
	// The icon must be set inside onReady: systray has not created the window
	// until then, and SetIcon is a no-op without it.
	systray.SetIcon(trayIconBytes(trayBodyForState("")))
	systray.SetTooltip(trayTooltip(agentStatus{State: "disconnected", Message: "Waiting for agent service"}))

	st, _ := readAgentStatus()
	applyStatus(st)

	statusItem := systray.AddMenuItem(st.label(), "Current agent state")
	statusItem.Disable()

	addAction("Version", "Tray "+version+" ("+buildDate+"), agent "+agentVersion(st), func() {
		message("AgentIde Agent",
			"Tray:  "+version+" ("+buildDate+")\r\n"+
				"Agent: "+agentVersion(st)+"\r\n"+
				"State: "+st.label())
	})

	systray.AddSeparator()
	addAction("Open Dashboard", "Open the AgentIde dashboard in your browser", func() { openURL(dashboardURL()) })
	addAction("Open Config", "Open agent config.json in Notepad", openConfig)
	addAction("Open Logs", "Open agentide.log in Notepad", openLogs)
	systray.AddSeparator()
	addAction("Restart Agent", "Stop and start the AgentIde service (needs elevation)", restartAgent)
	addAction("Service Status", "Show the service state of the agent and its guard", showServiceStatus)
	systray.AddSeparator()
	addAction("Quit Tray", "Remove the tray icon. The agent service keeps running.", func() { systray.Quit() })

	registerAutoStart()

	go func() {
		var current agentStatus
		for {
			st, err := readAgentStatus()
			if err != nil {
				st = agentStatus{State: "disconnected", Message: "Agent service not responding"}
			}
			if st != current {
				current = st
				applyStatus(st)
				statusItem.SetTitle(st.label())
				systray.SetTooltip(trayTooltip(st))
			}
			time.Sleep(pollInterval)
		}
	}()
}

func onExit() {}

// trayTooltip is the hover text. The agent's version is included because this is
// the only place the operator can check it without a console, and knowing which
// agent build is on the box is the first question when an assessment misbehaves.
func trayTooltip(st agentStatus) string {
	tip := "AgentIde - " + st.label()
	if v := strings.TrimSpace(st.Version); v != "" {
		tip += " (agent " + v + ")"
	}
	return tip
}

func agentVersion(st agentStatus) string {
	if v := strings.TrimSpace(st.Version); v != "" {
		return v
	}
	return "unknown"
}

// addAction adds a clickable menu item and runs fn on each click.
//
// systray signals clicks by sending on the item's channel rather than taking a
// callback, so the handler has to run in its own goroutine. The receive is
// repeated rather than fired once: a single receive would leave the tray
// deaf after the first click.
//
// The handler runs on this goroutine, which is deliberate. Several of these
// actions block - confirm() waits on a modal dialog, and the service helpers
// shell out - and doing that on systray's internal message dispatch would stall
// the whole tray, including its icon updates.
func addAction(title, tooltip string, fn func()) *systray.MenuItem {
	item := systray.AddMenuItem(title, tooltip)
	go func() {
		for range item.ClickedCh {
			fn()
		}
	}()
	return item
}

// applyStatus repaints the tray icon to reflect agent state. The same drawn
// glyph used on the status window is reused, recoloured per state.
func applyStatus(st agentStatus) {
	systray.SetIcon(trayIconBytes(trayBodyForState(st.State)))
	systray.SetTitle(st.stateDot() + " " + st.label())
}

// readAgentStatus connects to the named pipe, reads one JSON line and returns
// it. The agent writes a single newline-terminated object then closes.
func readAgentStatus() (agentStatus, error) {
	path, err := windows.UTF16PtrFromString(statusPipe)
	if err != nil {
		return agentStatus{}, err
	}

	h, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		0, 0,
	)
	if err != nil {
		return agentStatus{}, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 4096)
	var n uint32
	var ov windows.Overlapped

	// Bounded: a wedged agent must not hang the tray goroutine forever.
	done := make(chan error, 1)
	go func() { done <- windows.ReadFile(h, buf, &n, &ov) }()

	var readErr error
	select {
	case readErr = <-done:
	case <-time.After(pollTimeout):
		windows.CancelIoEx(h, nil)
		return agentStatus{}, fmt.Errorf("timeout reading status pipe")
	}
	if readErr != nil {
		return agentStatus{}, readErr
	}

	var st agentStatus
	line := strings.TrimSpace(string(buf[:n]))
	if err := json.Unmarshal([]byte(line), &st); err != nil {
		return agentStatus{}, err
	}
	return st, nil
}

// registerAutoStart ensures this user's Run key points at the tray, so the icon
// returns after a reboot.
//
// The installer no longer writes this itself: during an elevated install HKCU is
// the elevating administrator's hive, so other operators never got an icon.
// Registering from the tray means the account that runs it gets auto-start.
func registerAutoStart() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("autostart: cannot resolve own path: %v\n", err)
		return
	}
	command := "\"" + exe + "\""

	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("autostart: cannot open Run key: %v\n", err)
		return
	}
	defer k.Close()

	if existing, _, err := k.GetStringValue(autostartValue); err == nil && existing == command {
		return
	}
	if err := k.SetStringValue(autostartValue, command); err != nil {
		fmt.Printf("autostart: cannot write Run value: %v\n", err)
		return
	}
	fmt.Printf("autostart: registered for %s\n", os.Getenv("USERNAME"))
}

// dashboardURL returns the URL the agent actually reports to, so "Open
// Dashboard" works on an endpoint pointing at a remote dashboard.
func dashboardURL() string {
	if path, ok := firstExisting(configCandidates); ok {
		if data, err := os.ReadFile(path); err == nil {
			var cfg struct {
				DashboardURL string `json:"dashboard_url"`
			}
			if json.Unmarshal(data, &cfg) == nil && strings.TrimSpace(cfg.DashboardURL) != "" {
				return normaliseDashboardURL(cfg.DashboardURL)
			}
		}
	}
	return fallbackDash
}

func normaliseDashboardURL(u string) string {
	switch {
	case strings.HasPrefix(u, "wss://"):
		return "https://" + strings.TrimPrefix(u, "wss://")
	case strings.HasPrefix(u, "ws://"):
		return "http://" + strings.TrimPrefix(u, "ws://")
	default:
		return u
	}
}

func firstExisting(paths []string) (string, bool) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func openURL(url string) {
	exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

func openConfig() {
	if path, ok := firstExisting(configCandidates); ok {
		exec.Command("notepad.exe", path).Start()
		return
	}
	message("Config not found", "Could not find config.json in:\n"+strings.Join(configCandidates, "\n"))
}

func openLogs() {
	if path, ok := firstExisting(logCandidates); ok {
		exec.Command("notepad.exe", path).Start()
		return
	}
	message("Log not found", "Could not find agentide.log in:\n"+strings.Join(logCandidates, "\n"))
}

// restartAgent stops and starts the service. It needs elevation, so it is
// invoked through an explicit UAC prompt rather than failing silently with
// access denied.
func restartAgent() {
	if !confirm("Restart agent?", "This stops and starts the "+serviceName+" service.\n"+
		"The agent will briefly stop reporting to the dashboard.") {
		return
	}
	script := fmt.Sprintf(
		`Start-Process -Verb RunAs -Wait -FilePath sc.exe -ArgumentList 'stop','%s'; `+
			`Start-Sleep -Seconds 2; `+
			`Start-Process -Verb RunAs -Wait -FilePath sc.exe -ArgumentList 'start','%s'`,
		serviceName, serviceName)
	runHiddenElevated(script)
}

func showServiceStatus() {
	out, err := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
	if err != nil {
		message(serviceName+" service", "sc.exe query failed:\n"+err.Error())
		return
	}
	extra := ""
	if guard, gErr := exec.Command("sc.exe", "query", serviceNameAlt).CombinedOutput(); gErr == nil {
		extra = "\n\n" + serviceNameAlt + ":\n" + strings.TrimSpace(string(guard))
	}
	message(serviceName+" service", strings.TrimSpace(string(out))+extra)
}

func runHiddenElevated(script string) {
	exec.Command("powershell.exe", "-NoProfile", "-Command", script).Start()
}

func message(title, body string) {
	ps := fmt.Sprintf(
		"Add-Type -AssemblyName System.Windows.Forms; "+
			"[System.Windows.Forms.MessageBox]::Show(@'\n%s\n'@,'%s','OK','Information') | Out-Null",
		strings.ReplaceAll(body, "'", "''"), strings.ReplaceAll(title, "'", "''"))
	runHiddenElevated(ps)
}

func confirm(title, body string) bool {
	ps := fmt.Sprintf(
		"Add-Type -AssemblyName System.Windows.Forms; "+
			"$r=[System.Windows.Forms.MessageBox]::Show(@'\n%s\n'@,'%s','YesNo','Question'); "+
			"if($r -eq 'Yes'){exit 0}else{exit 1}",
		strings.ReplaceAll(body, "'", "''"), strings.ReplaceAll(title, "'", "''"))

	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", ps)
	if err := cmd.Run(); err != nil {
		return false
	}
	return cmd.ProcessState.ExitCode() == 0
}