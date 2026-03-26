package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/SimoneErrigo/Janus/backend/internal/api"
	"github.com/SimoneErrigo/Janus/backend/internal/cache"
	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
	"github.com/SimoneErrigo/Janus/backend/internal/sysstat"
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

	// Initialize Redis cache
	redisCache := cache.New(cfg.RedisAddr, cfg.RedisPassword)
	defer redisCache.Close()

	// Register cache invalidation on rule changes
	ruleStore.SetOnChange(func(serviceID string) {
		rules := ruleStore.ListRules(serviceID)
		redisCache.SetServiceRules(serviceID, rules)
		redisCache.InvalidatePacketQueries(serviceID)
	})

	// Register cache invalidation on new packet insertion
	packetStore.SetOnInsert(func(serviceID string) {
		redisCache.InvalidatePacketQueries(serviceID)
	})

	// Compile flag regex for packet flagging
	var flagRegex *regexp.Regexp
	if cfg.FlagRegex != "" {
		flagRegex, err = regexp.Compile(cfg.FlagRegex)
		if err != nil {
			log.Printf("Warning: invalid FLAG_REGEX %q: %v", cfg.FlagRegex, err)
		}
	}

	proxyMgr := proxy.NewManager(packetStore, ruleStore, flagRegex)
	proxyMgr.SetRulesCache(redisCache)

	services := store.ListServices()

	// Ensure flag rules exist and are corrected to alert-only for all services
	var serviceIDs []string
	for _, svc := range services {
		serviceIDs = append(serviceIDs, svc.ID)
	}
	dropper.EnsureFlagRulesForAll(ruleStore, serviceIDs, cfg.FlagRegex)

	// Populate Redis rules cache on startup
	redisCache.PopulateRules(ruleStore)

	// Auto-start enabled services
	for _, svc := range services {
		if svc.Enabled {
			if err := proxyMgr.StartService(svc); err != nil {
				log.Printf("Warning: failed to start service %s: %v", svc.Name, err)
			}
		}
	}

	// Start cleanup manager
	cleanupMgr := cleanup.NewManager(packetStore, cfg.CleanupMaxAgeMinutes, cfg.CleanupMaxDBSizeMB)
	cleanupMgr.Start()

	// Start flag ID poller
	flagIDPoller := flagids.NewPoller(cfg.FlagIDAPIURL, cfg.OurTeamID, cfg.FlagIDPollInterval, cfg.FlagIDEnabled)
	flagIDPoller.Start()

	statsCollector := sysstat.NewCollector(packetStore, redisCache, cfg.DataDir)
	apiServer := api.NewServer(store, proxyMgr, packetStore, ruleStore, cleanupMgr, flagIDPoller, redisCache, statsCollector)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		flagIDPoller.Stop()
		cleanupMgr.Stop()
		proxyMgr.StopAll()
		redisCache.Close()
		packetStore.Close()
		os.Exit(0)
	}()

	addr := ":" + cfg.APIPort
	log.Printf("Janus API listening on %s", addr)
	if err := http.ListenAndServe(addr, apiServer.Handler()); err != nil {
		log.Fatalf("API server error: %v", err)
	}
}
