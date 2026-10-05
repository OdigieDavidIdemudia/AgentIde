//go:build windows

package discovery

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listProcesses returns a map of process name (lowercase) -> processEntry for all running processes.
func listProcesses() (map[string]processEntry, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	result := make(map[string]processEntry)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("Process32First failed: %w", err)
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		result[strings.ToLower(name)] = processEntry{
			Name: name,
			PID:  int(entry.ProcessID),
		}

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break // No more processes
		}
	}

	return result, nil
}

// listServices returns a map of service name (lowercase) -> display name for all running services.
func listServices() (map[string]string, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager failed: %w", err)
	}
	defer windows.CloseServiceHandle(manager)

	var bytesNeeded, servicesReturned uint32
	var resumeHandle uint32

	// First call to get the required buffer size
	_ = windows.EnumServicesStatusEx(
		manager,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		nil,
		0,
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil,
	)

	buf := make([]byte, bytesNeeded)
	if err := windows.EnumServicesStatusEx(
		manager,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		&buf[0],
		uint32(len(buf)),
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil,
	); err != nil {
		return nil, fmt.Errorf("EnumServicesStatusEx failed: %w", err)
	}

	result := make(map[string]string)
	size := unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})
	for i := uint32(0); i < servicesReturned; i++ {
		svc := (*windows.ENUM_SERVICE_STATUS_PROCESS)(
			unsafe.Pointer(&buf[i*uint32(size)]),
		)
		name := windows.UTF16PtrToString(svc.ServiceName)
		displayName := windows.UTF16PtrToString(svc.DisplayName)
		result[strings.ToLower(name)] = displayName
	}

	return result, nil
}
