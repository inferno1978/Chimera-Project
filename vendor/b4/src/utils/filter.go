package utils

import "net"

func FilterUniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, d := range input {
		if !seen[d] {
			seen[d] = true
			result = append(result, d)
		}
	}

	return result
}

func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			ip4[0] == 127
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}
