package utils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/log"
)

// ValidatePorts takes a string of ports and port ranges (comma separated) and returns a validated string.
func ValidatePorts(ports string) string {
	if ports == "" {
		return ""
	}

	validPorts := []string{}

	portList := strings.Split(ports, ",")
	for _, portRange := range portList {
		portRange = strings.TrimSpace(portRange)
		portRange = strings.ReplaceAll(portRange, ":", "-")

		if strings.Contains(portRange, "-") {
			bounds := strings.Split(portRange, "-")
			if len(bounds) != 2 {
				log.Warnf("Invalid port range: %s", portRange)
				continue
			}

			start := strings.TrimSpace(bounds[0])
			end := strings.TrimSpace(bounds[1])

			startPort, err1 := strconv.Atoi(start)
			endPort, err2 := strconv.Atoi(end)

			if err1 != nil || err2 != nil || startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 {
				log.Warnf("Invalid port range: %s", portRange)
				continue
			}

			if startPort >= endPort {
				log.Warnf("Invalid port range (start >= end): %s", portRange)
				continue
			}

			validPorts = append(validPorts, fmt.Sprintf("%d-%d", startPort, endPort))
		} else {
			port := strings.TrimSpace(portRange)

			portNum, err := strconv.Atoi(port)
			if err != nil || portNum < 1 || portNum > 65535 {
				log.Warnf("Invalid port: %s", port)
				continue
			}

			validPorts = append(validPorts, port)
		}
	}

	return strings.Join(validPorts, ",")
}
