package blacklist

import (
	"encoding/json"
	"net/http"
	"time"
)

type Handler struct {
	bl *Blacklist
}

func NewHandler(bl *Blacklist) *Handler {
	return &Handler{bl: bl}
}

type Request struct {
	Entry    string `json:"entry"`
	BanType  string `json:"ban_type,omitempty"`
	Duration string `json:"duration,omitempty"`
}

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type ListData struct {
	IPs   []BanEntry `json:"ips"`
	CIDRs []BanEntry `json:"cidrs"`
}

type CheckData struct {
	Blacklisted bool      `json:"blacklisted"`
	BanEntry    *BanEntry `json:"ban_entry,omitempty"`
}

func (h *Handler) Add(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{Code: 405, Message: "method not allowed"})
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "invalid request body"})
		return
	}

	if req.Entry == "" {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "entry is required"})
		return
	}

	cfg := DefaultBanConfig()
	switch req.BanType {
	case "temporary":
		cfg.BanType = BanTemporary
		if req.Duration == "" {
			writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "duration is required for temporary ban"})
			return
		}
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "invalid duration format, use Go duration string like '24h', '30m'"})
			return
		}
		if d <= 0 {
			writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "duration must be positive"})
			return
		}
		cfg.Duration = d
	case "", "permanent":
		cfg.BanType = BanPermanent
	default:
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "invalid ban_type, must be 'temporary' or 'permanent'"})
		return
	}

	if err := h.bl.Add(req.Entry, cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, Response{Code: 0, Message: "added successfully"})
}

func (h *Handler) Remove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{Code: 405, Message: "method not allowed"})
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "invalid request body"})
		return
	}

	if req.Entry == "" {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "entry is required"})
		return
	}

	if err := h.bl.Remove(req.Entry); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, Response{Code: 0, Message: "removed successfully"})
}

func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, Response{Code: 405, Message: "method not allowed"})
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: "ip query parameter is required"})
		return
	}

	found, entry, err := h.bl.Contains(ip)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data: CheckData{
			Blacklisted: found,
			BanEntry:    entry,
		},
	})
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, Response{Code: 405, Message: "method not allowed"})
		return
	}

	ips, cidrs := h.bl.List()
	writeJSON(w, http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data:    ListData{IPs: ips, CIDRs: cidrs},
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(v)
}
