//go:build windows

package main

import (
	"fmt"

	"agentide/core"
	"agentide/guard"
	"agentide/service"

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
		// One agent per host. The service, the guardian and any manually
		// launched agent were all able to run at once, each evicting the
		// others' dashboard socket. A second instance now exits immediately.
		if ok, err := core.AcquireSingleInstance(); err != nil {
			fmt.Printf("[WARN] single-instance check failed, continuing: %v\n", err)
		} else if !ok {
			fmt.Println("[ERROR] another AgentIde instance is already running on this host; exiting")
			close(stopCh)
			return
		}

		// Re-apply the anti-tamper DACL on every startup so protection
		// survives a self-update (which temporarily widens the descriptor).
		// Done here, after SERVICE_RUNNING, so it cannot delay the SCM.
		if err := service.Harden(); err != nil {
			fmt.Printf("[WARN] Could not apply service protection: %v\n", err)
		}
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
	return svc.Run(service.ServiceName, &agentSvc{
		cfg:     cfg,
		mode:    mode,
		profile: profile,
		days:    days,
		module:  module,
	})
}

// guardSvc implements the self-protection guardian service.
type guardSvc struct{}

// Execute runs the guardian loop and stops cleanly on SCM stop/shutdown.
func (s *guardSvc) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		guard.Run(stopCh)
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(stopCh)
				<-done
				return false, 0
			}
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			// Release the Event Log handle before the SCM sees the service stop,
			// so it is not left to a process exiting with an open log.
			core.CloseEventLog()
			return false, 0
		}
	}
}

// runGuardService hands control to the SCM dispatcher under the guardian
// service name.
func runGuardService() error {
	return svc.Run(service.GuardServiceName, &guardSvc{})
}

// unprotectService widens the main service DACL for the duration of a
// self-update. Called by the detached updater via the -unprotect flag.
func unprotectService() error {
	return service.Unprotect()
}

// repairInstall ensures both AgentIde services exist, are enabled and running.
// Used by the scheduled task via the -repair flag.
func repairInstall() error {
	return service.Repair()
}
