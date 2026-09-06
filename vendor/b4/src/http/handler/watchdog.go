package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/watchdog"
)

type WatchdogDomainRequest struct {
	Domain string `json:"domain" example:"example.com"`
}

type WatchdogActionResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"added example.com to watchdog"`
}

func (api *API) RegisterWatchdogApi() {
	api.mux.HandleFunc("/api/watchdog/status", api.handleWatchdogStatus)
	api.mux.HandleFunc("/api/watchdog/check", api.handleWatchdogForceCheck)
	api.mux.HandleFunc("/api/watchdog/domains", api.handleWatchdogDomains)
	api.mux.HandleFunc("/api/watchdog/domains/{domain}", api.handleWatchdogDeleteDomain)
	api.mux.HandleFunc("/api/watchdog/enable", api.handleWatchdogEnable)
	api.mux.HandleFunc("/api/watchdog/disable", api.handleWatchdogDisable)
}

// @Summary Get watchdog status
// @Description Returns the current enabled state of the watchdog and the status of each monitored domain (last check, failures, cooldown, matched set, etc.).
// @Tags Watchdog
// @Produce json
// @Success 200 {object} watchdog.WatchdogState
// @Failure 405 {string} string "Method not allowed"
// @Security BearerAuth
// @Router /watchdog/status [get]
func (api *API) handleWatchdogStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if globalWatchdog == nil {
		setJsonHeader(w)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
			"domains": []interface{}{},
		})
		return
	}

	state := globalWatchdog.GetState()
	setJsonHeader(w)
	json.NewEncoder(w).Encode(state)
}

// @Summary Force an immediate watchdog check
// @Description Schedules an out-of-band check for a domain that is already present in the watchdog list. The domain may be passed as a bare host or a full URL; both forms are matched against the stored list.
// @Tags Watchdog
// @Accept json
// @Produce json
// @Param body body WatchdogDomainRequest true "Domain to force-check"
// @Success 200 {object} WatchdogActionResponse
// @Failure 400 {string} string "domain is required"
// @Failure 404 {string} string "domain not in watchdog list"
// @Failure 405 {string} string "Method not allowed"
// @Failure 503 {string} string "watchdog is not running"
// @Security BearerAuth
// @Router /watchdog/check [post]
func (api *API) handleWatchdogForceCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if globalWatchdog == nil {
		http.Error(w, "watchdog is not running", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	cfg := api.getCfg()
	found := false
	for _, d := range cfg.System.Checker.Watchdog.Domains {
		if d == domain || watchdog.ExtractDomain(d) == domain {
			found = true
			globalWatchdog.ForceCheck(d)
			break
		}
	}
	if !found {
		http.Error(w, "domain not in watchdog list", http.StatusNotFound)
		return
	}
	log.Infof("[WATCHDOG] forced check requested for %s", domain)

	setJsonHeader(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "check scheduled for " + domain,
	})
}

// @Summary Add a domain to the watchdog list
// @Description Adds a domain to the list of monitored targets. Duplicates (including different URL forms that resolve to the same host) are rejected. The configuration is persisted and pushed to running services.
// @Tags Watchdog
// @Accept json
// @Produce json
// @Param body body WatchdogDomainRequest true "Domain to add"
// @Success 200 {object} WatchdogActionResponse
// @Failure 400 {string} string "domain is required"
// @Failure 405 {string} string "Method not allowed"
// @Failure 409 {string} string "domain already in watchdog list"
// @Failure 500 {string} string "failed to save configuration"
// @Security BearerAuth
// @Router /watchdog/domains [post]
func (api *API) handleWatchdogDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	cfg := api.getCfg().Clone()
	domain := strings.ToLower(strings.TrimSpace(req.Domain))

	normalizedDomain := watchdog.ExtractDomain(domain)
	for _, d := range cfg.System.Checker.Watchdog.Domains {
		if d == domain || watchdog.ExtractDomain(d) == normalizedDomain {
			http.Error(w, "domain already in watchdog list", http.StatusConflict)
			return
		}
	}

	cfg.System.Checker.Watchdog.Domains = append(cfg.System.Checker.Watchdog.Domains, domain)
	if err := api.saveAndPushConfig(cfg); err != nil {
		log.Errorf("Failed to save watchdog config: %v", err)
		http.Error(w, "failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Infof("[WATCHDOG] added domain %s to watch list", domain)
	setJsonHeader(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "added " + domain + " to watchdog",
	})
}

// @Summary Remove a domain from the watchdog list
// @Description Removes a domain from the monitored list. The path parameter may be either the exact stored value or the bare host extracted from a stored URL.
// @Tags Watchdog
// @Produce json
// @Param domain path string true "Domain or host to remove"
// @Success 200 {object} WatchdogActionResponse
// @Failure 400 {string} string "domain is required"
// @Failure 404 {string} string "domain not found in watchdog list"
// @Failure 405 {string} string "Method not allowed"
// @Failure 500 {string} string "failed to save configuration"
// @Security BearerAuth
// @Router /watchdog/domains/{domain} [delete]
func (api *API) handleWatchdogDeleteDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	cfg := api.getCfg().Clone()
	found := false
	var filtered []string
	for _, d := range cfg.System.Checker.Watchdog.Domains {
		if d == domain || watchdog.ExtractDomain(d) == domain {
			found = true
			continue
		}
		filtered = append(filtered, d)
	}

	if !found {
		http.Error(w, "domain not found in watchdog list", http.StatusNotFound)
		return
	}

	cfg.System.Checker.Watchdog.Domains = filtered
	if err := api.saveAndPushConfig(cfg); err != nil {
		log.Errorf("Failed to save watchdog config: %v", err)
		http.Error(w, "failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Infof("[WATCHDOG] removed domain %s from watch list", domain)
	setJsonHeader(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "removed " + domain + " from watchdog",
	})
}

// @Summary Enable the watchdog
// @Description Turns the watchdog on and persists the change in the configuration. Monitoring of configured domains resumes on the next tick.
// @Tags Watchdog
// @Produce json
// @Success 200 {object} WatchdogActionResponse
// @Failure 405 {string} string "Method not allowed"
// @Failure 500 {string} string "failed to save configuration"
// @Security BearerAuth
// @Router /watchdog/enable [post]
func (api *API) handleWatchdogEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cfg := api.getCfg().Clone()
	cfg.System.Checker.Watchdog.Enabled = true
	if err := api.saveAndPushConfig(cfg); err != nil {
		log.Errorf("Failed to save watchdog config: %v", err)
		http.Error(w, "failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Infof("[WATCHDOG] enabled")
	setJsonHeader(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "watchdog enabled",
	})
}

// @Summary Disable the watchdog
// @Description Turns the watchdog off and persists the change in the configuration. No further domain checks are performed until it is re-enabled.
// @Tags Watchdog
// @Produce json
// @Success 200 {object} WatchdogActionResponse
// @Failure 405 {string} string "Method not allowed"
// @Failure 500 {string} string "failed to save configuration"
// @Security BearerAuth
// @Router /watchdog/disable [post]
func (api *API) handleWatchdogDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cfg := api.getCfg().Clone()
	cfg.System.Checker.Watchdog.Enabled = false
	if err := api.saveAndPushConfig(cfg); err != nil {
		log.Errorf("Failed to save watchdog config: %v", err)
		http.Error(w, "failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Infof("[WATCHDOG] disabled")
	setJsonHeader(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "watchdog disabled",
	})
}
