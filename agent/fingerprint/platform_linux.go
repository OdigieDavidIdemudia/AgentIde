//go:build linux

package fingerprint

import (
	"os"
	"strings"
	"syscall"
)

// platformVersion reads the Linux OS version from /etc/os-release and kernel from uname.
func platformVersion() (osVersion string, kernelBuild string) {
	osVersion = parseOSRelease()
	kernelBuild = kernelUname()
	return osVersion, kernelBuild
}

// parseOSRelease reads PRETTY_NAME from /etc/os-release.
func parseOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux (unknown)"
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			val = strings.Trim(val, `"`)
			return val
		}
	}
	return "Linux"
}

// kernelUname returns the kernel release string using the uname syscall.
func kernelUname() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "unknown"
	}

	buf := make([]byte, 0, len(uname.Release))
	for _, c := range uname.Release {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
