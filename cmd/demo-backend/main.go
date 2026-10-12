package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type echoRequest struct {
	Message string `json:"message"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		defer r.Body.Close()
		var input echoRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON request", http.StatusBadRequest)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "invalid JSON request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"echo": input.Message})
	})
	server := &http.Server{Addr: "127.0.0.1:9090", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	logger.Info("demo backend listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("serve demo backend", "error", err)
		os.Exit(1)
	}
}
