package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type PublicDNSServer struct {
	Reliability float64 `json:"reliability"`
	IP          string  `json:"ip"`
	Name        string  `json:"name"`
	Country     string  `json:"country_id"`
	City        string  `json:"city"`
	DNSSEC      bool    `json:"dnssec"`
}

func (api *API) RegisterDnsApi() {
	api.mux.HandleFunc("/api/dns", api.getPublicDNSServers)

}

// @Summary Get public DNS servers by country
// @Tags DNS
// @Produce json
// @Param country query string false "Country code (default: us)"
// @Success 200 {array} PublicDNSServer
// @Security BearerAuth
// @Router /dns [get]
func (api *API) getPublicDNSServers(w http.ResponseWriter, r *http.Request) {
	country := r.URL.Query().Get("country")
	if country == "" {
		country = "us"
	}

	url := fmt.Sprintf("https://public-dns.info/nameserver/%s.json", country)
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch DNS servers", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var servers []PublicDNSServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		http.Error(w, "Failed to parse DNS servers", http.StatusInternalServerError)
		return
	}

	var filtered []PublicDNSServer
	for _, s := range servers {
		if s.Reliability < 0.90 || !s.DNSSEC {
			continue
		}
		// Skip IPv6 if disabled
		if !api.getCfg().Queue.IPv6Enabled && strings.Contains(s.IP, ":") {
			continue
		}
		filtered = append(filtered, s)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Reliability > filtered[j].Reliability
	})

	if len(filtered) > 30 {
		filtered = filtered[:30]
	}

	setJsonHeader(w)
	json.NewEncoder(w).Encode(filtered)
}
