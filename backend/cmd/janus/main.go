package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/api"
	"github.com/SimoneErrigo/Janus/backend/internal/cache"
	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
	"github.com/SimoneErrigo/Janus/backend/internal/scoring"
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
	packetStore.SetFlowCorrelationWindowSec(cfg.FlowCorrelationWindowSec)

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

	// Compile flag regex for packet flagging. When case-insensitivity is
	// requested (env flag or an inline "(?i)"), ensure the compiled fallback
	// regex honors it too.
	effectiveFlagPattern := cfg.FlagRegex
	if cfg.FlagRegexCaseInsensitive && effectiveFlagPattern != "" &&
		!strings.HasPrefix(effectiveFlagPattern, "(?i)") {
		effectiveFlagPattern = "(?i)" + effectiveFlagPattern
	}
	var flagRegex *regexp.Regexp
	if effectiveFlagPattern != "" {
		flagRegex, err = regexp.Compile(effectiveFlagPattern)
		if err != nil {
			log.Printf("Warning: invalid FLAG_REGEX %q: %v", cfg.FlagRegex, err)
		}
	}

	// Build optimized flag scanner from the regex pattern
	flagScanner := flagids.NewFlagScanner(cfg.FlagRegex, cfg.FlagRegexCaseInsensitive, cfg.FlagDecodeURL)
	if flagScanner != nil {
		log.Printf("Flag scanner active for pattern %q (case_insensitive=%v, decode_url=%v)",
			cfg.FlagRegex, cfg.FlagRegexCaseInsensitive, cfg.FlagDecodeURL)
	}

	proxyMgr := proxy.NewManager(packetStore, ruleStore, flagRegex, flagScanner)
	proxyMgr.SetDataPlaneBindMode(cfg.DataPlane.BindMode)
	proxyMgr.SetRulesCache(redisCache)
	captureCtrl := sniffer.NewCaptureController(cfg.TrafficMode)
	proxyMgr.SetCaptureController(captureCtrl)

	services := store.ListServices()

	// Populate Redis rules cache on startup
	redisCache.PopulateRules(ruleStore)

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
		cfg.FlagIDAPIURL, cfg.OurTeamID, cfg.FlagIDPollInterval, cfg.FlagIDEnabled, cfg.FlagIDFormat,
		cfg.RoundDurationSec, competitionStart, cfg.KeepRounds,
	)
	packetStore.SetRoundResolver(flagIDPoller.RoundForTime)
	serviceBaselineRanges := make(map[string]scoring.BaselineRange, len(cfg.BaselineServiceRounds))
	for serviceID, rounds := range cfg.BaselineServiceRounds {
		serviceBaselineRanges[serviceID] = scoring.BaselineRange{StartRound: rounds.StartRound, EndRound: rounds.EndRound}
	}
	baselineConfig := scoring.NewBaselineConfig(
		competitionStart, cfg.RoundDurationSec, cfg.BaselineStartRound, cfg.BaselineEndRound, serviceBaselineRanges,
	)
	scoreEngine := scoring.NewWithEnabled(packetStore, baselineConfig, cfg.ScoringEnabled)
	defer scoreEngine.Close()

	// Hub created after the poller so streamed packets carry their round
	// (computed from competition_start + round_duration). Pushed packets
	// happen via the listener below — but no packets flow yet because the
	// proxy services aren't started until further down.
	packetHub := api.NewPacketStreamHub(flagIDPoller)
	packetStore.SetScoreChangeListener(packetHub.PushScoreUpdate)

	// Python filter engine (mitmproxy-style scriptable filtering). Matches are
	// recorded as alerts (rule_id "pyfilter:<script>"), evaluated asynchronously
	// off the proxy hot path. Inert until the operator enables a script.
	pyMgr := pyfilter.NewManager(pyfilter.Config{
		DataDir:    cfg.DataDir,
		PythonPath: cfg.PyFilterPython,
		OnMatch: func(flow pyfilter.Flow, m pyfilter.Match) {
			pid, _ := flow["id"].(int64)
			svcID, _ := flow["service"].(string)
			srcIP, _ := flow["src"].(string)
			reason := m.Name
			if m.Reason != "" {
				reason = m.Name + ": " + m.Reason
			}
			alert := &sniffer.Alert{
				PacketID:       pid,
				RuleID:         "pyfilter:" + m.Script,
				ServiceID:      svcID,
				SrcIP:          srcIP,
				Timestamp:      time.Now(),
				PatternMatched: reason,
			}
			if err := packetStore.InsertAlert(alert); err != nil {
				log.Printf("pyfilter: failed to record alert: %v", err)
				return
			}
			packetHub.Notify()
		},
	})
	pyMgr.SetRuntimeEnabled(cfg.PyFilterEnabled)
	defer pyMgr.Close()
	st := pyMgr.Status()
	if !st.Enabled {
		log.Printf("Python filters paused (native Go drop/alert rules remain active)")
	} else if st.Available {
		log.Printf("Python filters enabled (interpreter: %s)", st.PythonPath)
	} else {
		log.Printf("Python filters enabled but no python3 interpreter found — scripts will not run")
	}

	// Inline filters run synchronously before forwarding so drop, close, and
	// rewrite decisions can affect the current message. Evaluation is bounded
	// and fail-open inside EvaluateBlocking.
	reconcilePyFlow := func(flow map[string]any) { pyMgr.ReconcileBlocking(pyfilter.Flow(flow)) }
	proxyMgr.SetPyBlockFn(func(flow map[string]any) sniffer.PyResult {
		matches, newBody := pyMgr.EvaluateBlocking(flow)
		res := sniffer.PyResult{Finalize: reconcilePyFlow}
		for _, mt := range matches {
			if mt.Error {
				continue
			}
			reason := mt.Name
			if mt.Reason != "" {
				reason = mt.Name + ": " + mt.Reason
			}
			match := sniffer.PyBlockMatch{Script: mt.Script, Reason: reason, Close: mt.Close}
			if mt.Block {
				res.Blocks = append(res.Blocks, match)
			} else {
				res.Alerts = append(res.Alerts, match)
			}
		}
		if newBody != nil {
			res.NewBody = newBody
			res.Rewritten = true
		}
		return res
	})
	proxyMgr.SetPyShouldEvaluateFn(pyMgr.ShouldEvaluateBlocking)

	packetStore.SetPacketChangeListener(func(kind sniffer.PacketChangeKind, pkt *sniffer.Packet) {
		if kind == sniffer.PacketChangeInsert && pkt != nil {
			packetHub.PushPacket(pkt)
			scoreEngine.Submit(pkt)
			if pyMgr != nil && pyMgr.ShouldSubmitAsync(pkt.ServiceID, pkt.Protocol) {
				pyMgr.Submit(api.FlowFromPacket(pkt))
			}
		} else {
			packetHub.Notify()
		}
	})
	flagIDPoller.SetOnFetch(func(currentRound int) {
		if captureCtrl.Mode() != sniffer.TrafficModeLive {
			return
		}
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
	if pyMgr != nil {
		serviceIDs := make([]string, 0, len(services))
		for _, svc := range services {
			if svc.Enabled {
				serviceIDs = append(serviceIDs, svc.ID)
			}
		}
		if err := pyMgr.PrewarmServices(serviceIDs); err != nil {
			log.Printf("Warning: failed to prewarm Python filters: %v", err)
		}
	}
	for _, svc := range services {
		if svc.Enabled {
			if err := proxyMgr.StartService(svc); err != nil {
				log.Printf("Warning: failed to start service %s: %v", svc.Name, err)
			}
		}
	}

	if cfg.TrafficMode == sniffer.TrafficModeLive {
		flagIDPoller.Start()
	}

	// Start cleanup manager
	cleanupMgr := cleanup.NewManager(packetStore, cfg.CleanupMaxAgeMinutes, cfg.CleanupMaxDBSizeMB)
	if cfg.TrafficMode == sniffer.TrafficModeStatic {
		cleanupMgr.UpdateSettings(cleanup.Settings{MaxAgeMinutes: 0, MaxDBSizeMB: 0})
	}
	cleanupMgr.Start()

	statsCollector := sysstat.NewCollector(packetStore, redisCache, cfg.DataDir)
	apiServer := api.NewServer(store, proxyMgr, packetStore, ruleStore, cleanupMgr, flagIDPoller, redisCache, statsCollector, packetHub, captureCtrl, cfg.ProtoDir, pyMgr)
	apiServer.SetScoringStatusProvider(scoreEngine)

	addr := cfg.ControlPlane.Bind + ":" + cfg.ControlPlane.Port
	httpServer := &http.Server{
		Addr: addr, Handler: apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- httpServer.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	log.Printf("Janus API listening on %s", addr)
	var fatalServerErr error
	select {
	case sig := <-sigCh:
		log.Printf("Shutting down after %s...", sig)
	case serveErr := <-serverErr:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fatalServerErr = serveErr
			log.Printf("API server error: %v", serveErr)
		}
	}

	// Stop streams first so long-lived SSE requests don't hold HTTP shutdown
	// open, then stop every producer before draining the persistence pipeline.
	packetHub.Stop()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown timed out: %v", err)
		_ = httpServer.Close()
	}
	cancelShutdown()

	flagIDPoller.Stop()
	cleanupMgr.Stop()
	proxyMgr.StopAll()

	importsCtx, cancelImports := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := apiServer.WaitForPcapImports(importsCtx); err != nil {
		log.Printf("PCAP import drain timed out: %v", err)
	}
	cancelImports()

	packetStore.Drain()
	if pyMgr != nil {
		pyMgr.Close()
	}
	scoreEngine.Close()
	if err := packetStore.Close(); err != nil {
		log.Printf("packet store close error: %v", err)
	}
	if err := redisCache.Close(); err != nil {
		log.Printf("Redis close error: %v", err)
	}
	log.Println("Shutdown complete")
	if fatalServerErr != nil {
		// Cleanup has completed; report a failing process status so Compose,
		// systemd, and Kubernetes restart a control plane that never bound.
		log.Fatalf("Janus API stopped unexpectedly: %v", fatalServerErr)
	}
}
