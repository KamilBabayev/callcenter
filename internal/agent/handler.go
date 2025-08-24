package agent

import (
	"callcenter/internal/db"
	"encoding/json"
	"net/http"
)

var allowedStatuses = map[string]bool{
	"online":  true,
	"busy":    true,
	"offline": true,
}

type StatusUpdateRequest struct {
	AgentID int    `json:"agent_id"`
	Status  string `json:"status"`
}

func UpdateStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StatusUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.AgentID <= 0 {
		http.Error(w, "Valid agent_id is required", http.StatusBadRequest)
		return
	}
	if !allowedStatuses[req.Status] {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	if err := UpdateAgentStatus(database, req.AgentID, req.Status); err != nil {
		http.Error(w, "Error updating agent status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Agent status updated successfully!\n"))
}
