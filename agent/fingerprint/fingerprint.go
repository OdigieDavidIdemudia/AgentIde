package fingerprint

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Fingerprint holds all identifying information about the endpoint.
type Fingerprint struct {
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	OS          string    `json:"os"`
	OSVersion   string    `json:"os_version"`
	KernelBuild string    `json:"kernel_build"`
	Arch        string    `json:"arch"`
	CollectedAt time.Time `json:"collected_at"`
}

// Collect gathers endpoint metadata and returns a populated Fingerprint.
// It delegates OS-specific fields (OSVersion, KernelBuild) to platform-specific files.
func Collect() (*Fingerprint, error) {
	fp := &Fingerprint{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC(),
	}

	// Hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	fp.Hostname = hostname

	// Primary IP and MAC address
	ip, mac, err := primaryInterface()
	if err != nil {
		fp.IP = "unknown"
		fp.MAC = "unknown"
	} else {
		fp.IP = ip
		fp.MAC = mac
	}

	// OS version and kernel build (platform-specific)
	fp.OSVersion, fp.KernelBuild = platformVersion()

	return fp, nil
}

// ToMap converts the Fingerprint into a map suitable for structured logging.
func (f *Fingerprint) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"hostname":     f.Hostname,
		"ip":           f.IP,
		"mac":          f.MAC,
		"os":           f.OS,
		"os_version":   f.OSVersion,
		"kernel_build": f.KernelBuild,
		"arch":         f.Arch,
	}
}

// primaryInterface returns the IP and MAC of the first non-loopback, active network interface.
func primaryInterface() (ip string, mac string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("cannot enumerate network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ipStr string
			switch v := addr.(type) {
			case *net.IPNet:
				ipStr = v.IP.String()
			case *net.IPAddr:
				ipStr = v.IP.String()
			}

			// Prefer IPv4, skip link-local
			if strings.Contains(ipStr, ":") || strings.HasPrefix(ipStr, "169.254") {
				continue
			}

			return ipStr, iface.HardwareAddr.String(), nil
		}
	}

	return "unknown", "unknown", fmt.Errorf("no suitable network interface found")
}
