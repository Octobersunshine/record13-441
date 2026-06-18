package blacklist

import (
	"encoding/json"
	"net/http"
)

type Handler struct {
	bl *Blacklist
}

func NewHandler(bl *Blacklist) *Handler {
	return &Handler{bl: bl}
}

type Request struct {
	Entry string `json:"entry"`
}

type Response struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Data    any      `json:"data,omitempty"`
}

type ListData struct {
	IPs   []string `json:"ips"`
	CIDRs []string `json:"cidrs"`
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

	if err := h.bl.Add(req.Entry); err != nil {
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

	found, err := h.bl.Contains(ip)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data:    map[string]bool{"blacklisted": found},
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
