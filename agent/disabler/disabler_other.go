//go:build !windows

package disabler

import "fmt"

// DisableResult holds the outcome of a disable attempt.
type DisableResult struct {
	Vendor    string
	Disabled  bool
	Notes     string
}

// Disable is a no-op stub on non-Windows platforms.
func Disable(vendor string) (DisableResult, func()) {
	return DisableResult{
		Vendor:   vendor,
		Disabled: false,
		Notes:    fmt.Sprintf("Disabling %q is not supported on this platform", vendor),
	}, func() {}
}

// Enable is a no-op stub on non-Windows platforms.
func Enable(vendor string) error {
	return fmt.Errorf("Enabling %q is not supported on this platform", vendor)
}

// SupportedVendors returns an empty list on non-Windows platforms.
func SupportedVendors() []string {
	return nil
}
