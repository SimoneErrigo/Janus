package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimoneErrigo/Janus/backend/internal/api"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
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

	packetStore, err := sniffer.NewPacketStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize packet store: %v", err)
	}
	defer packetStore.Close()

	ruleStore, err := dropper.NewRuleStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize rule store: %v", err)
	}

	proxyMgr := proxy.NewManager(packetStore, ruleStore)

	// Auto-start enabled services
	for _, svc := range store.ListServices() {
		if svc.Enabled {
			if err := proxyMgr.StartService(svc); err != nil {
				log.Printf("Warning: failed to start service %s: %v", svc.Name, err)
			}
		}
	}

	apiServer := api.NewServer(store, proxyMgr, packetStore, ruleStore)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		proxyMgr.StopAll()
		packetStore.Close()
		os.Exit(0)
	}()

	addr := ":" + cfg.APIPort
	log.Printf("Janus API listening on %s", addr)
	if err := http.ListenAndServe(addr, apiServer.Handler()); err != nil {
		log.Fatalf("API server error: %v", err)
	}
}
