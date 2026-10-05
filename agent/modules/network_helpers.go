package modules

import (
	"fmt"
	"net"
	"time"
)

// scanLocalhostPorts tries to connect to localhost on each port and returns open ones.
// This is cross-platform and shared between Windows and Linux helpers.
func scanLocalhostPorts(ports []int) []int {
	var open []int
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			open = append(open, port)
		}
	}
	return open
}
