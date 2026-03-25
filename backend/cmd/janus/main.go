package main

import (
	"log"
	"os"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
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

	log.Printf("Janus starting — VM_IP=%s, API port=%s", cfg.VMIP, cfg.APIPort)
}
