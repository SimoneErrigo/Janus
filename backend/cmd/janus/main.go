package main

import (
	"log"
	"net/http"
	"os"

	"github.com/SimoneErrigo/Janus/backend/internal/api"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func main() {
	envPath := ".env"
	if v := os.Getenv("ENV_PATH"); v != "" {
		envPath = v
	}

	cfg, err := config.Load(envPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	apiServer := api.NewServer(store)

	addr := ":" + cfg.APIPort
	log.Printf("Janus API listening on %s", addr)
	if err := http.ListenAndServe(addr, apiServer.Handler()); err != nil {
		log.Fatalf("API server error: %v", err)
	}
}
