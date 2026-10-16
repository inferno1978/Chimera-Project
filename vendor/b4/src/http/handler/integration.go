package handler

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/daniellavrushin/b4/log"
)

func (api *API) RegisterIntegrationApi() {
	api.mux.HandleFunc("/api/integration/ipinfo", api.getIpInfo)
	api.mux.HandleFunc("/api/integration/ripestat/asn", api.getRipestatAsnPrefixes)
	api.mux.HandleFunc("/api/integration/ripestat", api.getRipestatNetworkInfo)
}

// @Summary Query IPInfo API for IP details
// @Tags Integration
// @Produce json
// @Param ip query string true "IP address"
// @Success 200 {object} object
// @Security BearerAuth
// @Router /integration/ipinfo [get]
func (a *API) getIpInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP parameter required", http.StatusBadRequest)
		return
	}

	token := a.getCfg().System.API.IPInfoToken
	if token == "" {
		http.Error(w, "IPInfo token not configured", http.StatusBadRequest)
		return
	}

	cleanIP := ip
	if host, _, err := net.SplitHostPort(cleanIP); err == nil {
		cleanIP = host
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", cleanIP, token)
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Failed to fetch IP info: %v", err)
		http.Error(w, "Failed to fetch IP info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "IPInfo API error", resp.StatusCode)
		return
	}

	setJsonHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// @Summary Query RIPE ASN announced prefixes
// @Tags Integration
// @Produce json
// @Param asn query string true "ASN number"
// @Success 200 {object} object
// @Security BearerAuth
// @Router /integration/ripestat/asn [get]
func (a *API) getRipestatAsnPrefixes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	asn := r.URL.Query().Get("asn")
	if asn == "" {
		http.Error(w, "ASN parameter required", http.StatusBadRequest)
		return
	}

	// Remove AS/ASN prefix if present
	asn = strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "N")

	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Failed to fetch RIPE ASN prefixes: %v", err)
		http.Error(w, "Failed to fetch ASN prefixes", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "RIPE API error", resp.StatusCode)
		return
	}

	setJsonHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// @Summary Query RIPE network info for IP
// @Tags Integration
// @Produce json
// @Param ip query string true "IP address"
// @Success 200 {object} object
// @Security BearerAuth
// @Router /integration/ripestat [get]
func (a *API) getRipestatNetworkInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP parameter required", http.StatusBadRequest)
		return
	}

	cleanIP := ip
	if host, _, err := net.SplitHostPort(cleanIP); err == nil {
		cleanIP = host
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	url := fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", cleanIP)
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Failed to fetch RIPE network info: %v", err)
		http.Error(w, "Failed to fetch network info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "RIPE API error", resp.StatusCode)
		return
	}

	setJsonHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}
