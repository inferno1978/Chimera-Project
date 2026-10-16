package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

func (api *API) RegisterAsnApi() {
	api.mux.HandleFunc("/api/asn", api.handleAsn)
	api.mux.HandleFunc("/api/asn/lookup", api.handleAsnLookup)
}

func (a *API) handleAsn(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getAsnAll(w, r)
	case http.MethodPut:
		a.putAsn(w, r)
	case http.MethodDelete:
		a.deleteAsn(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// @Summary Get all ASN entries
// @Tags ASN
// @Produce json
// @Success 200 {array} config.AsnInfo
// @Security BearerAuth
// @Router /asn [get]
func (a *API) getAsnAll(w http.ResponseWriter, _ *http.Request) {
	sendResponse(w, a.asnStore.GetAll())
}

// @Summary Create or update ASN entry
// @Tags ASN
// @Accept json
// @Produce json
// @Param body body config.AsnInfo true "ASN info"
// @Success 200 {object} config.AsnInfo
// @Security BearerAuth
// @Router /asn [put]
func (a *API) putAsn(w http.ResponseWriter, r *http.Request) {
	var info config.AsnInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if info.ID == "" {
		writeJsonError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := a.asnStore.Set(&info); err != nil {
		writeJsonError(w, http.StatusInternalServerError, "failed to save ASN data")
		return
	}
	sendResponse(w, info)
}

// @Summary Delete ASN entry
// @Tags ASN
// @Produce json
// @Param id query string true "ASN ID"
// @Success 200 {object} object
// @Security BearerAuth
// @Router /asn [delete]
func (a *API) deleteAsn(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJsonError(w, http.StatusBadRequest, "id parameter required")
		return
	}
	if err := a.asnStore.Delete(id); err != nil {
		writeJsonError(w, http.StatusInternalServerError, "failed to delete ASN data")
		return
	}
	sendResponse(w, map[string]bool{"ok": true})
}

// @Summary Lookup ASN by IP address
// @Tags ASN
// @Produce json
// @Param ip query string true "IP address"
// @Success 200 {object} config.AsnInfo
// @Security BearerAuth
// @Router /asn/lookup [get]
func (a *API) handleAsnLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJsonError(w, http.StatusBadRequest, "ip parameter required")
		return
	}

	cleanIP := ip
	if idx := strings.Index(cleanIP, ":"); idx != -1 {
		if !strings.Contains(cleanIP, "::") && strings.Count(cleanIP, ":") == 1 {
			cleanIP = cleanIP[:idx]
		}
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	info := a.asnStore.FindByIP(cleanIP)
	if info == nil {
		sendResponse(w, nil)
		return
	}
	sendResponse(w, info)
}
