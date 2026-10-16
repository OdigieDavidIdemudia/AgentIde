// Command agentide-tray is the system tray companion for the AgentIde agent.
//
// It is a separate process from the agent service, so it learns what the agent
// is doing by connecting to the status named pipe the agent serves
// (\\.\pipe\agentide). The agent publishes one small JSON object per connection
// and the tray polls, which keeps the agent free of client bookkeeping and
// lets the tray be started or restarted at any time.
//
// Previously this program built a window and a tray context menu but never
// attached the menu, never updated its status label, and connected to a named
// pipe the agent never created — so every control was inert. It also pointed
// "Open Dashboard" at a hardcoded localhost, which is wrong on an endpoint
// that reports to a remote dashboard.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	statusPipe     = `\\.\pipe\agentide`
	serviceName    = "AgentIde"
	fallbackDash   = "https://localhost:8443"
	pollInterval   = 3 * time.Second
	serviceNameAlt = "AgentIdeGuard"
)

// configCandidates are the paths the installer and the service have used for
// config.json, newest layout first. The installer writes the service config
// next to the executable; older installs used ProgramData.
var (
	configCandidates = []string{
		`C:\Program Files\AgentIde\config.json`,
		`C:\ProgramData\AgentIde\config.json`,
	}
	logCandidates = []string{
		`C:\Program Files\AgentIde\agentide.log`,
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

// label returns a short human description for the tray and the window.
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

// stateColour keeps the status text readable at a glance.
func (s agentStatus) stateColour() string {
	switch s.State {
	case "connected":
		return "#1a7f37"
	case "connecting", "assessing":
		return "#9a6700"
	default:
		return "#b42318"
	}
}

type mainWindow struct {
	*walk.MainWindow
	statusLabel  *walk.Label
	detailLabel  *walk.Label
	versionLabel *walk.Label
	trayIcon     *walk.NotifyIcon
}

func main() {
	mw := &mainWindow{}

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "AgentIde Agent",
		MinSize:  Size{Width: 360, Height: 210},
		Layout:   VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		Children: []Widget{
			Label{
				Text:      "AgentIde EDR Assessment Agent",
				Font:      Font{PointSize: 10, Bold: true},
				Alignment: AlignHCenterVNear,
			},
			HSplitter{
				MinSize: Size{Width: 340, Height: 4},
				Children: []Widget{
					Label{Text: ""},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					Label{Text: "Status:", MinSize: Size{Width: 70, Height: 0}},
					Label{AssignTo: &mw.statusLabel, Text: "Waiting for agent service..."},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					Label{Text: "", MinSize: Size{Width: 70, Height: 0}},
					Label{AssignTo: &mw.detailLabel, Text: ""},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					Label{Text: "", MinSize: Size{Width: 70, Height: 0}},
					Label{AssignTo: &mw.versionLabel, Text: ""},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 12, Right: 4, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					PushButton{Text: "Open Dashboard", OnClicked: mw.openDashboard},
					PushButton{Text: "Open Config", OnClicked: mw.openConfig},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					PushButton{Text: "Open Logs", OnClicked: mw.openLogs},
					PushButton{Text: "Restart Agent", OnClicked: mw.restartAgent},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 12}, Spacing: 8},
				Children: []Widget{
					PushButton{Text: "Service Status", OnClicked: mw.showServiceStatus},
					PushButton{Text: "Hide", OnClicked: func() { hideToTray(mw) }},
				},
			},
		},
	}.Create()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create UI: %v\n", err)
		os.Exit(1)
	}

	mw.createTray()

	// Register auto-start for *this* user.
	//
	// The installer writes HKCU\...\Run, but HKCU during an elevated install
	// is the elevating administrator's hive, not the operator's. Any other user
	// who signs in afterwards never gets the icon. Registering from the tray
	// itself means the account actually running it gets auto-start, which is
	// what "the icon is always there" requires.
	registerAutoStart()

	// Poll the agent's status pipe in the background and refresh the UI.
	go mw.pollStatus()

	mw.Run()
}

// runKey is the per-user auto-start location.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// registerAutoStart ensures this user's Run key points at the tray, so the
// notification icon returns after a reboot without a manual shortcut.
//
// Failures are logged and otherwise ignored: a missing icon is a papercut, and
// refusing to run the tray because of a registry write would be worse.
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

	// Only write when it differs, so the registry is not marked dirty on
	// every launch.
	if existing, _, err := k.GetStringValue("AgentIde Tray"); err == nil && existing == command {
		return
	}
	if err := k.SetStringValue("AgentIde Tray", command); err != nil {
		fmt.Printf("autostart: cannot write Run value: %v\n", err)
		return
	}
	fmt.Printf("autostart: registered for %s\n", os.Getenv("USERNAME"))
}

// pollStatus connects to the agent's status pipe on a timer. A failed connect
// is normal (the service may be stopped), so it is reported as a state rather
// than treated as an error.
func (mw *mainWindow) pollStatus() {
	for {
		st, err := readAgentStatus()
		if err != nil {
			st = agentStatus{State: "disconnected", Message: "Agent service not responding"}
		}
		mw.applyStatus(st)
		time.Sleep(pollInterval)
	}
}

func (mw *mainWindow) applyStatus(st agentStatus) {
	text := st.label()
	detail := st.Hostname
	if detail == "" {
		detail = "hostname unknown"
	}
	if st.DashboardURL != "" {
		detail += "  ·  " + st.DashboardURL
	}
	version := "version unknown"
	if st.Version != "" {
		version = "v" + st.Version
	}
	if st.AssessmentActive {
		version += "  ·  assessment running"
	}

	mw.Synchronize(func() {
		if mw.statusLabel != nil {
			if err := mw.statusLabel.SetText(text); err != nil {
				fmt.Printf("status label: %v\n", err)
			}
		}
		if mw.detailLabel != nil {
			mw.detailLabel.SetText(detail)
		}
		if mw.versionLabel != nil {
			mw.versionLabel.SetText(version)
		}
	})

	if mw.trayIcon != nil {
		mw.trayIcon.SetToolTip("AgentIde - " + text)
		// Recolour the shield to match state so the icon itself carries
		// information rather than being decoration.
		if img, err := buildTrayIconWithBody(trayIconSize, trayIconForState(st.State)); err == nil {
			mw.trayIcon.SetIcon(img)
		}
	}
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
		0,
		0,
	)
	if err != nil {
		return agentStatus{}, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 4096)
	var n uint32
	var ov windows.Overlapped
	// The pipe server writes immediately and closes; a plain ReadFile with an
	// overlapped handle completes synchronously in practice for a message pipe
	// of this size. Guard with a read deadline via CancelIoEx on timeout.
	done := make(chan error, 1)
	go func() {
		e := windows.ReadFile(h, buf, &n, &ov)
		done <- e
	}()

	select {
	case e := <-done:
		if e != nil {
			return agentStatus{}, e
		}
	case <-time.After(3 * time.Second):
		windows.CancelIoEx(h, nil)
		return agentStatus{}, fmt.Errorf("timeout reading status pipe")
	}

	var st agentStatus
	line := strings.TrimSpace(string(buf[:n]))
	if err := json.Unmarshal([]byte(line), &st); err != nil {
		return agentStatus{}, err
	}
	return st, nil
}

// createTray builds the notification icon and attaches the context menu.
//
// walk.NotifyIcon keeps its contextMenu field unexported and offers no
// SetContextMenu in this version, but walk's property reflection can still set
// it — without this the tray icon appeared but right-clicking did nothing,
// which is what the previous build shipped.
func (mw *mainWindow) createTray() {
	icon, err := walk.NewNotifyIcon(mw.MainWindow)
	if err != nil {
		return
	}
	mw.trayIcon = icon
	icon.SetToolTip("AgentIde - Waiting for agent service")

	// An icon with no image is invisible in the notification area. There is no
	// .ico asset in the repository and the agent exe carries no icon resource,
	// so the glyph is composed here instead — which also means it always matches
	// the current theme rather than needing a design file kept in step with it.
	if img, err := buildTrayIcon(trayIconSize); err == nil {
		if err := icon.SetIcon(img); err != nil {
			fmt.Printf("could not set tray icon: %v\n", err)
		}
	} else {
		fmt.Printf("could not build tray icon: %v\n", err)
	}

	icon.SetVisible(true)

	menu, err := walk.NewMenu()
	if err != nil {
		return
	}

	addAction(menu, "Open Dashboard", mw.openDashboard, true)
	addAction(menu, "Open Config", mw.openConfig, true)
	addAction(menu, "Open Logs", mw.openLogs, true)
	menu.Actions().Add(walk.NewSeparatorAction())
	addAction(menu, "Show AgentIde", func() { mw.restore() }, true)
	addAction(menu, "Restart Agent", mw.restartAgent, true)
	addAction(menu, "Service Status", mw.showServiceStatus, true)
	menu.Actions().Add(walk.NewSeparatorAction())
	addAction(menu, "Quit Tray", func() { walk.App().Exit(0) }, true)

	// Attach the menu. walk.NotifyIcon keeps contextMenu unexported and provides
	// no setter or reflection helper, so it is written directly. Without this the
	// tray icon rendered but right-clicking did nothing, which is what the previous
	// build shipped.
	if err := setNotifyIconMenu(icon, menu); err != nil {
		// Left-click still restores the window, so the app stays usable.
		fmt.Printf("could not attach tray menu: %v\n", err)
	}

	icon.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			mw.restore()
		}
	})
}

// setNotifyIconMenu writes walk.NotifyIcon's unexported contextMenu field.
//
// walk exposes no exported setter and no SetPropertyValue helper in this
// version, and the field is not settable through normal reflection, so this
// uses unsafe to reach it. It is the only way to make the tray icon's
// right-click menu work at all; the alternative is a tray icon that silently
// ignores clicks.
func setNotifyIconMenu(icon *walk.NotifyIcon, menu *walk.Menu) error {
	v := reflect.ValueOf(icon).Elem().FieldByName("contextMenu")
	if !v.IsValid() {
		return fmt.Errorf("walk.NotifyIcon has no contextMenu field in this version")
	}
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(menu))
	return nil
}

func addAction(menu *walk.Menu, text string, fn func(), enabled bool) {
	a := walk.NewAction()
	a.SetText(text)
	a.SetEnabled(enabled)
	a.Triggered().Attach(fn)
	menu.Actions().Add(a)
}

func hideToTray(mw *mainWindow) {
	mw.SetVisible(false)
}

func (mw *mainWindow) restore() {
	// Form has no portable SetForeground in walk, so making the window visible
	// is the whole of "restore" here. On a multi-monitor setup the operator may
	// still need to alt-tab, which is why the tray icon is also clickable.
	mw.SetVisible(true)
}

// dashboardURL returns the URL the agent actually reports to, so "Open
// Dashboard" works on an endpoint pointing at a remote dashboard. Falls back
// to localhost only when no config can be read.
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

// normaliseDashboardURL converts a ws:// or wss:// agent URL into the https://
// origin a browser can open.
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
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func (mw *mainWindow) openDashboard() {
	openURL(dashboardURL())
}

func (mw *mainWindow) openConfig() {
	if path, ok := firstExisting(configCandidates); ok {
		runVisible("notepad.exe", path)
		return
	}
	message("Config not found", "Could not find config.json in:\n"+strings.Join(configCandidates, "\n"))
}

func (mw *mainWindow) openLogs() {
	if path, ok := firstExisting(logCandidates); ok {
		runVisible("notepad.exe", path)
		return
	}
	message("Log not found", "Could not find agentide.log in:\n"+strings.Join(logCandidates, "\n"))
}

// restartAgent restarts the service. This needs elevation, so it is invoked
// through a PowerShell elevation prompt rather than silently failing.
func (mw *mainWindow) restartAgent() {
	if !confirm("Restart agent?", "This stops and starts the "+serviceName+" service.\nThe agent will briefly stop reporting to the dashboard.") {
		return
	}
	// sc.exe needs admin. Use Start-Process -Verb RunAs so the UAC prompt is
	// explicit rather than the command silently failing with access denied.
	script := fmt.Sprintf(
		`Start-Process -Verb RunAs -Wait -FilePath sc.exe -ArgumentList 'stop','%s'; Start-Sleep -Seconds 2; Start-Process -Verb RunAs -Wait -FilePath sc.exe -ArgumentList 'start','%s'`,
		serviceName, serviceName)
	runHiddenElevated(script)
}

func (mw *mainWindow) showServiceStatus() {
	out, err := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
	title := serviceName + " service"
	if err != nil {
		message(title, "sc.exe query failed:\n"+err.Error())
		return
	}
	extra := ""
	if guardOut, gErr := exec.Command("sc.exe", "query", serviceNameAlt).CombinedOutput(); gErr == nil {
		extra = "\n\n" + serviceNameAlt + ":\n" + strings.TrimSpace(string(guardOut))
	}
	message(title, strings.TrimSpace(string(out))+extra)
}

func openURL(url string) {
	exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

func runVisible(name string, args ...string) {
	exec.Command(name, args...).Start()
}

// runHiddenElevated runs a PowerShell snippet with a UAC elevation prompt.
func runHiddenElevated(script string) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		message("Restart failed", err.Error())
	}
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
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return false
	}
	return cmd.ProcessState.ExitCode() == 0
}
