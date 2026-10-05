//go:build windows

package fingerprint

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// platformVersion reads the Windows OS version and build number from the registry.
func platformVersion() (osVersion string, kernelBuild string) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "Windows (unknown)", "unknown"
	}
	defer k.Close()

	productName, _, pErr := k.GetStringValue("ProductName")
	if pErr != nil || productName == "" {
		productName = "Windows"
	}
	currentBuild, _, cbErr := k.GetStringValue("CurrentBuild")
	if cbErr != nil || currentBuild == "" {
		currentBuild = "unknown"
	}
	ubr, _, ubrErr := k.GetIntegerValue("UBR") // Update Build Revision
	if ubrErr != nil {
		ubr = 0 // Missing UBR is normal on older builds, or registry read failed
	}

	// Microsoft kept the ProductName as "Windows 10" for Windows 11 internally.
	// Any build >= 22000 is actually Windows 11.
	// Note: This string replacement only triggers on "Windows 10" SKUs.
	// Windows Server SKUs (e.g., Server 2022 -> 2025 equivalents) will not be
	// automatically mapped by this logic and will require explicit server mapping.
	if strings.Contains(productName, "Windows 10") {
		buildInt, err := strconv.Atoi(currentBuild)
		if err == nil && buildInt >= 22000 {
			productName = strings.Replace(productName, "Windows 10", "Windows 11", 1)
		}
	}

	kernelBuild = fmt.Sprintf("%s.%d", currentBuild, ubr)
	return productName, kernelBuild
}
