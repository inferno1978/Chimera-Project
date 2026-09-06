package tables

import (
	"fmt"

	"github.com/daniellavrushin/b4/config"
)

type discoveryBackend interface {
	name() string
	available() bool
	apply(flowMark uint, injectedMark uint, queueStart int, threads int) error
	clear(flowMark uint, injectedMark uint)
}

func getDiscoveryBackend(cfg *config.Config) discoveryBackend {
	backend := detectFirewallBackend(cfg)
	nft := &discoveryNftBackend{}
	ipt := &discoveryIptBackend{legacy: backend == backendIPTablesLegacy}

	switch backend {
	case backendNFTables:
		if nft.available() {
			return nft
		}
	default:
		if ipt.available() {
			return ipt
		}
	}

	if nft.available() {
		return nft
	}
	if ipt.available() {
		return ipt
	}
	return nil
}

func ApplyDiscoverySteeringRules(cfg *config.Config, flowMark uint, injectedMark uint, queueStart int, threads int) error {
	be := getDiscoveryBackend(cfg)
	if be == nil {
		return fmt.Errorf("no discovery firewall backend available")
	}
	return be.apply(flowMark, injectedMark, queueStart, threads)
}

func ClearDiscoverySteeringRules(cfg *config.Config, flowMark uint, injectedMark uint) {
	be := getDiscoveryBackend(cfg)
	if be == nil {
		return
	}
	be.clear(flowMark, injectedMark)
}
