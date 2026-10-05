//go:build windows

package main

import (
	"agentide/core"

	"golang.org/x/sys/windows/svc"
)

// agentSvc implements the svc.Handler interface required by the Windows SCM.
type agentSvc struct {
	cfg     *core.Config
	mode    string
	profile string
	days    int
	module  string
}

// Execute is called by the Windows SCM when the service starts.
// It must signal SERVICE_RUNNING to SCM within 30 seconds, then block until stop.
func (s *agentSvc) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// 1. Immediately report START_PENDING so SCM knows we are alive
	changes <- svc.Status{State: svc.StartPending}

	// 2. Run all startup logic (fingerprint, discovery, transport) in the background
	stopCh := make(chan struct{})
	go func() {
		runAgent(s.cfg, s.mode, s.profile, s.days, s.module)
		close(stopCh)
	}()

	// 3. Signal SERVICE_RUNNING — SCM is satisfied, no more Error 1053
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// 4. Block waiting for SCM stop/shutdown signal
	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		case <-stopCh:
			// Agent run loop exited on its own
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

// runAsWindowsService hands control to the Windows SCM dispatcher.
func runAsWindowsService(cfg *core.Config, mode, profile string, days int, module string) error {
	return svc.Run("AgentIde", &agentSvc{
		cfg:     cfg,
		mode:    mode,
		profile: profile,
		days:    days,
		module:  module,
	})
}
