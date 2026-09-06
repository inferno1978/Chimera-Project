package dhcp

// ARPEntry represents a device discovered from the ARP table.
type ARPEntry struct {
	IP     string
	MAC    string
	Device string // network interface (e.g. "br0")
}

// LeaseUpdateCallback is called when the IP-to-MAC mapping changes.
type LeaseUpdateCallback func(ipToMAC map[string]string)
