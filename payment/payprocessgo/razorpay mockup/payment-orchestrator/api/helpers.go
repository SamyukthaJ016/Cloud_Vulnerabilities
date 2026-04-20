package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// writeJSON is the only place we write JSON responses
// Never duplicate this in other handlers
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON encode error: %v", err)
	}
}

// writeError writes a consistent error shape
// {"error": "message"}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
