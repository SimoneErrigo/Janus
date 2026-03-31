package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

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
	})

	// Compile flag regex for packet flagging
	var flagRegex *regexp.Regexp
	if cfg.FlagRegex != "" {
		flagRegex, err = regexp.Compile(cfg.FlagRegex)
		if err != nil {
			log.Printf("Warning: invalid FLAG_REGEX %q: %v", cfg.FlagRegex, err)
		}
	}

	// Build optimized flag scanner from the regex pattern
	flagScanner := flagids.NewFlagScanner(cfg.FlagRegex)
	if flagScanner != nil {
		log.Printf("Flag scanner: optimized byte-level scanner active for pattern %q", cfg.FlagRegex)
	}

	proxyMgr := proxy.NewManager(packetStore, ruleStore, flagRegex, flagScanner)
	proxyMgr.SetRulesCache(redisCache)

	services := store.ListServices()

	// Populate Redis rules cache on startup
	redisCache.PopulateRules(ruleStore)

	packetHub := api.NewPacketStreamHub()
	packetStore.SetPacketChangeListener(func(kind sniffer.PacketChangeKind, pkt *sniffer.Packet) {
		if kind == sniffer.PacketChangeInsert && pkt != nil {
			packetHub.PushPacket(pkt)
		} else {
			packetHub.Notify()
		}
	})

	// Parse competition start time if configured
	var competitionStart time.Time
	if cfg.CompetitionStart != "" {
		if t, parseErr := time.Parse(time.RFC3339, cfg.CompetitionStart); parseErr == nil {
			competitionStart = t
			log.Printf("Competition start: %s", competitionStart.Format(time.RFC3339))
		} else {
			log.Printf("Warning: invalid COMPETITION_START %q: %v", cfg.CompetitionStart, parseErr)
		}
	}

	flagIDPoller := flagids.NewPoller(
		cfg.FlagIDAPIURL, cfg.OurTeamID, cfg.FlagIDPollInterval, cfg.FlagIDEnabled,
		cfg.RoundDurationSec, competitionStart, cfg.KeepRounds,
	)
	flagIDPoller.SetOnFetch(func(currentRound int) {
		// Smart backfill: re-scan only packets from the limbo window using AC automaton
		n, backfillErr := packetStore.SmartBackfillFlagIDs(flagIDPoller, currentRound)
		if backfillErr != nil {
			log.Printf("auto-backfill error: %v", backfillErr)
		}
		if n > 0 {
			log.Printf("auto-backfill: updated %d packets for round %d", n, currentRound)
		}
		packetHub.Notify()
	})
	proxyMgr.SetFlagIDChecker(flagIDPoller)

	// Auto-start enabled services (flag-ID checker must be set before middleware is built)
	for _, svc := range services {
		if svc.Enabled {
			if err := proxyMgr.StartService(svc); err != nil {
				log.Printf("Warning: failed to start service %s: %v", svc.Name, err)
			}
		}
	}

	flagIDPoller.Start()

	// Start cleanup manager
	cleanupMgr := cleanup.NewManager(packetStore, cfg.CleanupMaxAgeMinutes, cfg.CleanupMaxDBSizeMB)
	cleanupMgr.Start()

	statsCollector := sysstat.NewCollector(packetStore, redisCache, cfg.DataDir)
	apiServer := api.NewServer(store, proxyMgr, packetStore, ruleStore, cleanupMgr, flagIDPoller, redisCache, statsCollector, packetHub)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		packetHub.Stop()
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
