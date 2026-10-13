package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

const (
	configPath   = `C:\ProgramData\AgentIde\config.json`
	dashboardURL = "https://localhost:8443"
)

var (
	agentStatus = "Disconnected"
)

type MyMainWindow struct {
	*walk.MainWindow
	statusLabel *walk.Label
}

func main() {
	mw := &MyMainWindow{}

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "AgentIde Tray",
		MinSize:  Size{200, 100},
		Layout:   VBox{},
		Children: []Widget{
			Label{
				Text:      "AgentIde EDR Assessment Agent",
				Alignment: AlignHCenterVNear,
				Font:      Font{PointSize: 10, Bold: true},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					Label{Text: "Status:"},
					Label{AssignTo: &mw.statusLabel, Text: "Disconnected"},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text:      "Open Dashboard",
						OnClicked: mw.openDashboard,
					},
					PushButton{
						Text:      "Open Config",
						OnClicked: mw.openConfig,
					},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text:      "Open Logs",
						OnClicked: mw.openLogs,
					},
					PushButton{
						Text:      "Restart Agent",
						OnClicked: mw.restartAgent,
					},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text:      "Service Status",
						OnClicked: mw.showServiceStatus,
					},
					PushButton{
						Text:      "Quit Tray",
						OnClicked: func() { mw.Close() },
					},
				},
			},
		},
	}.Create()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create UI: %v\n", err)
		os.Exit(1)
	}

	// Create system tray icon
	createTray(mw)

	// Start connection to agent
	go connectToAgent()

	mw.Run()
}

func (mw *MyMainWindow) openDashboard() {
	openURL(dashboardURL)
}

func (mw *MyMainWindow) openConfig() {
	openConfig()
}

func (mw *MyMainWindow) openLogs() {
	openLogs()
}

func (mw *MyMainWindow) restartAgent() {
	restartAgent()
}

func (mw *MyMainWindow) showServiceStatus() {
	showServiceStatus()
}

var (
	trayIcon *walk.NotifyIcon
	trayMenu *walk.Menu
)

func createTray(mw *MyMainWindow) {
	var err error
	trayIcon, err = walk.NewNotifyIcon(mw.MainWindow)
	if err != nil {
		fmt.Printf("Failed to create tray icon: %v\n", err)
		return
	}
	trayIcon.SetToolTip("AgentIde - Disconnected")
	trayIcon.SetVisible(true)

	trayMenu, _ = walk.NewMenu()

	// Status item (disabled)
	statusAction := walk.NewAction()
	statusAction.SetText("Status: Disconnected")
	statusAction.SetEnabled(false)
	trayMenu.Actions().Add(statusAction)

	trayMenu.Actions().Add(walk.NewSeparatorAction())

	// Dashboard
	dashboardAction := walk.NewAction()
	dashboardAction.SetText("Open Dashboard")
	dashboardAction.Triggered().Attach(func() { openURL(dashboardURL) })
	trayMenu.Actions().Add(dashboardAction)

	// Config
	configAction := walk.NewAction()
	configAction.SetText("Open Config")
	configAction.Triggered().Attach(func() { openConfig() })
	trayMenu.Actions().Add(configAction)

	// Logs
	logsAction := walk.NewAction()
	logsAction.SetText("Open Logs")
	logsAction.Triggered().Attach(func() { openLogs() })
	trayMenu.Actions().Add(logsAction)

	trayMenu.Actions().Add(walk.NewSeparatorAction())

	// Restart
	restartAction := walk.NewAction()
	restartAction.SetText("Restart Agent")
	restartAction.Triggered().Attach(func() { restartAgent() })
	trayMenu.Actions().Add(restartAction)

	// Service Status
	statusAction2 := walk.NewAction()
	statusAction2.SetText("Service Status")
	statusAction2.Triggered().Attach(func() { showServiceStatus() })
	trayMenu.Actions().Add(statusAction2)

	trayMenu.Actions().Add(walk.NewSeparatorAction())

	// Quit
	quitAction := walk.NewAction()
	quitAction.SetText("Quit Tray")
	quitAction.Triggered().Attach(func() { walk.App().Exit(0) })
	trayMenu.Actions().Add(quitAction)

	// Note: walk.NotifyIcon doesn't have SetContextMenu in this version
	trayIcon.SetToolTip("AgentIde - Disconnected")
	trayIcon.SetVisible(true)
}

// IPC connection to agent service
func connectToAgent() {
	for {
		// Wait for pipe to be available
		pipeHandle, err := windows.CreateFile(
			syscall.StringToUTF16Ptr(`\\.\pipe\agentide`),
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0,
		)

		if err != nil {
			updateStatus("Disconnected")
			time.Sleep(5 * time.Second)
			continue
		}

		// Successfully connected
		updateStatus("Connected")

		// Read from pipe
		buf := make([]byte, 4096)
		var overlapped windows.Overlapped
		for {
			var n uint32
			err := windows.ReadFile(pipeHandle, buf, &n, &overlapped)
			if err != nil {
				break
			}
			if n > 0 {
				handlePipeMessage(buf[:n])
			}
		}

		windows.CloseHandle(pipeHandle)
		time.Sleep(2 * time.Second)
	}
}

func handlePipeMessage(data []byte) {
	// Parse JSON message from agent
	// Update status based on message type
}

func updateStatus(s string) {
	fmt.Printf("Status: %s\n", s)
}

func openURL(url string) {
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	cmd.Run()
}

func openConfig() {
	configPath := `C:\ProgramData\AgentIde\config.json`
	cmd := exec.Command("notepad.exe", configPath)
	cmd.Run()
}

func openLogs() {
	logPath := `C:\ProgramData\AgentIde\agentide.log`
	cmd := exec.Command("notepad.exe", logPath)
	cmd.Run()
}

func restartAgent() {
	cmd := exec.Command("sc.exe", "stop", "AgentIde")
	cmd.Run()
	time.Sleep(2 * time.Second)
	cmd = exec.Command("sc.exe", "start", "AgentIde")
	cmd.Run()
}

func showServiceStatus() {
	cmd := exec.Command("sc.exe", "query", "AgentIde")
	output, _ := cmd.CombinedOutput()

	psScript := fmt.Sprintf(`
	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.MessageBox]::Show(%q, "AgentIde Service Status", "OK", "Information")
	`, string(output))
	exec.Command("powershell.exe", "-Command", psScript).Run()
}

func showError(title, msg string) {
	psScript := fmt.Sprintf(`
	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.MessageBox]::Show(%q, %q, "OK", "Error")
	`, msg, title)
	exec.Command("powershell.exe", "-Command", psScript).Run()
}