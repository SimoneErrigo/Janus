package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type ControlPlaneConfig struct {
	Bind string
	Port string
}

type DataPlaneConfig struct {
	DefaultBind string
	BindMode    string
}

type BaselineRoundRange struct {
	StartRound int `json:"start_round"`
	EndRound   int `json:"end_round"`
}

// Config holds the global configuration loaded from .env.
type Config struct {
	TeamPassword string
	FlagRegex    string
	// FlagRegexCaseInsensitive matches flags regardless of ASCII case. A
	// leading "(?i)" in FlagRegex implies the same thing.
	FlagRegexCaseInsensitive bool
	// FlagDecodeURL also scans a percent-decoded copy of the traffic so
	// URL-encoded flags (e.g. "...%3D" instead of "...=") are still caught.
	FlagDecodeURL bool
	DataDir       string
	APIPort       string
	APIBind       string
	ControlPlane  ControlPlaneConfig
	DataPlane     DataPlaneConfig

	// TeamIP is our team's address on the competition network. When a
	// service's listen address omits the host (e.g. ":8080" or just a port),
	// the proxy binds it to TeamIP instead of every interface.
	TeamIP       string
	DataBindMode string

	// Cleanup settings
	CleanupMaxAgeMinutes int
	CleanupMaxDBSizeMB   int

	// Flag ID settings
	FlagIDEnabled      bool
	OurTeamID          string
	FlagIDAPIURL       string
	FlagIDPollInterval int // seconds
	FlagIDFormat       string

	// Competition timing
	RoundDurationSec      int                           // duration of a single round in seconds (default 120)
	CompetitionStart      string                        // when the competition started (RFC3339, optional)
	KeepRounds            int                           // how many rounds of flagIds to keep (default 5)
	BaselineStartRound    int                           // default first baseline round (inclusive)
	BaselineEndRound      int                           // default last baseline round (inclusive)
	BaselineServiceRounds map[string]BaselineRoundRange // optional service-specific overrides

	// Redis settings
	RedisAddr     string
	RedisPassword string

	// Traffic capture mode
	TrafficMode string // "live" | "static"

	// Flow reconstruction
	FlowCorrelationWindowSec int // correlation time window in seconds

	// PCAP export
	PcapExportDir string // directory for exported .pcap files (default: {DataDir}/pcap)
	PcapAutoSave  bool   // if true, auto-export when static capture stops

	// gRPC / protobuf decoding
	ProtoDir string // directory scanned at runtime for .proto files (default /protos)

	// Python filters (mitmproxy-style scriptable filtering)
	PyFilterEnabled bool   // master switch (default true)
	PyFilterPython  string // interpreter path override (default: auto-detect python3)
}

var (
	instance    *Config
	instanceErr error
	once        sync.Once
	mu          sync.RWMutex
)

const runtimeConfigName = "runtime_config.json"

// runtimeConfig is deliberately limited to settings editable from the UI.
// Infrastructure-only values (bind addresses, Redis credentials, data path,
// interpreter path, ...) remain controlled by the environment.
type runtimeConfig struct {
	TeamPassword             *string                       `json:"team_password,omitempty"`
	FlagRegex                *string                       `json:"flag_regex,omitempty"`
	CleanupMaxAgeMinutes     *int                          `json:"cleanup_max_age_minutes,omitempty"`
	CleanupMaxDBSizeMB       *int                          `json:"cleanup_max_db_size_mb,omitempty"`
	FlagIDEnabled            *bool                         `json:"flagid_enabled,omitempty"`
	OurTeamID                *string                       `json:"our_team_id,omitempty"`
	FlagIDAPIURL             *string                       `json:"flagid_api_url,omitempty"`
	FlagIDPollInterval       *int                          `json:"flagid_poll_interval,omitempty"`
	FlagIDFormat             *string                       `json:"flagid_format,omitempty"`
	RoundDurationSec         *int                          `json:"round_duration_seconds,omitempty"`
	CompetitionStart         *string                       `json:"competition_start,omitempty"`
	KeepRounds               *int                          `json:"keep_rounds,omitempty"`
	BaselineStartRound       *int                          `json:"baseline_start_round,omitempty"`
	BaselineEndRound         *int                          `json:"baseline_end_round,omitempty"`
	BaselineServiceRounds    map[string]BaselineRoundRange `json:"baseline_service_rounds,omitempty"`
	TrafficMode              *string                       `json:"traffic_mode,omitempty"`
	FlowCorrelationWindowSec *int                          `json:"flow_correlation_window_seconds,omitempty"`
	PcapExportDir            *string                       `json:"pcap_export_dir,omitempty"`
	PcapAutoSave             *bool                         `json:"pcap_auto_save,omitempty"`
}

// Load reads the .env file and returns the Config singleton.
func Load(envPath string) (*Config, error) {
	once.Do(func() {
		cfg := &Config{
			// Defaults
			TeamPassword:             "changeme",
			FlagRegex:                "[A-Z0-9]{31}=",
			FlagDecodeURL:            true,
			DataDir:                  "/data",
			APIPort:                  "8080",
			APIBind:                  "0.0.0.0",
			TrafficMode:              "live",
			FlowCorrelationWindowSec: 120,
			FlagIDPollInterval:       5,
			FlagIDFormat:             "cyberchallenge",
			RoundDurationSec:         120,
			KeepRounds:               5,
			BaselineStartRound:       1,
			BaselineEndRound:         5,
			BaselineServiceRounds:    make(map[string]BaselineRoundRange),
			ProtoDir:                 "/protos",
			PyFilterEnabled:          true,
			DataBindMode:             "configured",
		}

		env, err := parseEnvFile(envPath)
		if err != nil {
			// .env is optional; use defaults if missing
			if !os.IsNotExist(err) {
				instanceErr = fmt.Errorf("parsing .env: %w", err)
				return
			}
		}

		if v, ok := env["TEAM_PASSWORD"]; ok {
			cfg.TeamPassword = v
		}
		if v, ok := env["FLAG_REGEX"]; ok {
			cfg.FlagRegex = v
		}
		if v, ok := env["FLAG_REGEX_CASE_INSENSITIVE"]; ok {
			cfg.FlagRegexCaseInsensitive = boolVal(v)
		}
		if v, ok := env["FLAG_DECODE_URL"]; ok {
			cfg.FlagDecodeURL = boolVal(v)
		}
		if v, ok := env["TEAM_IP"]; ok {
			cfg.TeamIP = strings.TrimSpace(v)
		}
		if v, ok := env["DATA_BIND_MODE"]; ok && v != "" {
			cfg.DataBindMode = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := env["DATA_DIR"]; ok {
			cfg.DataDir = v
		}
		if v, ok := env["API_PORT"]; ok {
			cfg.APIPort = v
		}
		if v, ok := env["API_BIND"]; ok && v != "" {
			cfg.APIBind = v
		}
		if v, ok := env["CLEANUP_MAX_AGE_MINUTES"]; ok {
			cfg.CleanupMaxAgeMinutes, _ = strconv.Atoi(v)
		}
		if v, ok := env["CLEANUP_MAX_DB_SIZE_MB"]; ok {
			cfg.CleanupMaxDBSizeMB, _ = strconv.Atoi(v)
		}
		if v, ok := env["FLAGID_ENABLED"]; ok {
			cfg.FlagIDEnabled = strings.EqualFold(v, "true") || v == "1"
		}
		if v, ok := env["OUR_TEAM_ID"]; ok {
			cfg.OurTeamID = v
		}
		if v, ok := env["FLAGID_API_URL"]; ok {
			cfg.FlagIDAPIURL = v
		}
		if v, ok := env["FLAGID_POLL_INTERVAL"]; ok {
			cfg.FlagIDPollInterval, _ = strconv.Atoi(v)
		}
		if v, ok := env["FLAGID_FORMAT"]; ok && v != "" {
			cfg.FlagIDFormat = strings.ToLower(v)
		}
		if v, ok := env["ROUND_DURATION"]; ok {
			cfg.RoundDurationSec, _ = strconv.Atoi(v)
		}
		if v, ok := env["COMPETITION_START"]; ok {
			cfg.CompetitionStart = v
		}
		if v, ok := env["KEEP_ROUNDS"]; ok {
			cfg.KeepRounds, _ = strconv.Atoi(v)
		}
		if v, ok := env["BASELINE_START_ROUND"]; ok {
			cfg.BaselineStartRound, _ = strconv.Atoi(v)
		}
		if v, ok := env["BASELINE_END_ROUND"]; ok {
			cfg.BaselineEndRound, _ = strconv.Atoi(v)
		}
		if v, ok := env["REDIS_ADDR"]; ok {
			cfg.RedisAddr = v
		}
		if v, ok := env["REDIS_PASSWORD"]; ok {
			cfg.RedisPassword = v
		}
		if v, ok := env["TRAFFIC_MODE"]; ok && v != "" {
			cfg.TrafficMode = strings.ToLower(v)
		}
		if v, ok := env["FLOW_CORRELATION_WINDOW_SECONDS"]; ok && v != "" {
			cfg.FlowCorrelationWindowSec, _ = strconv.Atoi(v)
		}
		if v, ok := env["PCAP_EXPORT_DIR"]; ok && v != "" {
			cfg.PcapExportDir = v
		}
		if v, ok := env["PCAP_AUTO_SAVE"]; ok {
			cfg.PcapAutoSave = strings.EqualFold(v, "true") || v == "1"
		}
		if v, ok := env["PROTO_DIR"]; ok && v != "" {
			cfg.ProtoDir = v
		}
		if v, ok := env["PYFILTER_ENABLED"]; ok {
			cfg.PyFilterEnabled = boolVal(v)
		}
		if v, ok := env["PYFILTER_PYTHON"]; ok && v != "" {
			cfg.PyFilterPython = strings.TrimSpace(v)
		}

		// Environment variables override .env file
		if v := os.Getenv("TEAM_PASSWORD"); v != "" {
			cfg.TeamPassword = v
		}
		if v := os.Getenv("FLAG_REGEX"); v != "" {
			cfg.FlagRegex = v
		}
		if v := os.Getenv("FLAG_REGEX_CASE_INSENSITIVE"); v != "" {
			cfg.FlagRegexCaseInsensitive = boolVal(v)
		}
		if v := os.Getenv("FLAG_DECODE_URL"); v != "" {
			cfg.FlagDecodeURL = boolVal(v)
		}
		if v := os.Getenv("TEAM_IP"); v != "" {
			cfg.TeamIP = strings.TrimSpace(v)
		}
		if v := os.Getenv("DATA_BIND_MODE"); v != "" {
			cfg.DataBindMode = strings.ToLower(strings.TrimSpace(v))
		}
		if v := os.Getenv("DATA_DIR"); v != "" {
			cfg.DataDir = v
		}
		if v := os.Getenv("API_PORT"); v != "" {
			cfg.APIPort = v
		}
		if v := os.Getenv("API_BIND"); v != "" {
			cfg.APIBind = v
		}
		if v := os.Getenv("CLEANUP_MAX_AGE_MINUTES"); v != "" {
			cfg.CleanupMaxAgeMinutes, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("CLEANUP_MAX_DB_SIZE_MB"); v != "" {
			cfg.CleanupMaxDBSizeMB, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("FLAGID_ENABLED"); v != "" {
			cfg.FlagIDEnabled = strings.EqualFold(v, "true") || v == "1"
		}
		if v := os.Getenv("OUR_TEAM_ID"); v != "" {
			cfg.OurTeamID = v
		}
		if v := os.Getenv("FLAGID_API_URL"); v != "" {
			cfg.FlagIDAPIURL = v
		}
		if v := os.Getenv("FLAGID_POLL_INTERVAL"); v != "" {
			cfg.FlagIDPollInterval, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("FLAGID_FORMAT"); v != "" {
			cfg.FlagIDFormat = strings.ToLower(v)
		}
		if v := os.Getenv("ROUND_DURATION"); v != "" {
			cfg.RoundDurationSec, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("COMPETITION_START"); v != "" {
			cfg.CompetitionStart = v
		}
		if v := os.Getenv("KEEP_ROUNDS"); v != "" {
			cfg.KeepRounds, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("BASELINE_START_ROUND"); v != "" {
			cfg.BaselineStartRound, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("BASELINE_END_ROUND"); v != "" {
			cfg.BaselineEndRound, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("REDIS_ADDR"); v != "" {
			cfg.RedisAddr = v
		}
		if v := os.Getenv("REDIS_PASSWORD"); v != "" {
			cfg.RedisPassword = v
		}
		if v := os.Getenv("TRAFFIC_MODE"); v != "" {
			cfg.TrafficMode = strings.ToLower(v)
		}
		if v := os.Getenv("FLOW_CORRELATION_WINDOW_SECONDS"); v != "" {
			cfg.FlowCorrelationWindowSec, _ = strconv.Atoi(v)
		}
		if v := os.Getenv("PCAP_EXPORT_DIR"); v != "" {
			cfg.PcapExportDir = v
		}
		if v := os.Getenv("PCAP_AUTO_SAVE"); v != "" {
			cfg.PcapAutoSave = strings.EqualFold(v, "true") || v == "1"
		}
		if v := os.Getenv("PROTO_DIR"); v != "" {
			cfg.ProtoDir = v
		}
		if v := os.Getenv("PYFILTER_ENABLED"); v != "" {
			cfg.PyFilterEnabled = boolVal(v)
		}
		if v := os.Getenv("PYFILTER_PYTHON"); v != "" {
			cfg.PyFilterPython = strings.TrimSpace(v)
		}

		// Values explicitly saved from the dashboard survive restarts. They are
		// applied after the environment because the dashboard is the latest
		// operator intent; infrastructure-only settings are never persisted here.
		if err := loadRuntimeConfig(cfg); err != nil {
			instanceErr = err
			return
		}
		normalizeDefaults(cfg)

		// Derive PcapExportDir default from DataDir if not set
		if cfg.PcapExportDir == "" {
			cfg.PcapExportDir = cfg.DataDir + "/pcap"
		}
		// Materialize the logical plane split while preserving the legacy env
		// variables as the public configuration surface.
		materializePlanes(cfg)

		mu.Lock()
		instance = cfg
		mu.Unlock()
	})

	if instanceErr != nil {
		return nil, instanceErr
	}
	return Get(), nil
}

// Get returns an immutable snapshot of the loaded configuration. Callers can
// safely retain or modify their copy without racing with runtime updates.
func Get() *Config {
	mu.RLock()
	defer mu.RUnlock()
	if instance == nil {
		panic("config.Load() must be called before config.Get()")
	}
	copy := *instance
	copy.BaselineServiceRounds = cloneBaselineServiceRounds(instance.BaselineServiceRounds)
	return &copy
}

// Update validates through mutate, atomically persists the next dashboard
// configuration, and only then publishes it. A failed save leaves both the
// in-memory and on-disk configuration unchanged.
func Update(mutate func(*Config) error) (*Config, error) {
	if mutate == nil {
		return Get(), nil
	}
	mu.Lock()
	defer mu.Unlock()
	if instance == nil {
		return nil, fmt.Errorf("config.Load() must be called before config.Update()")
	}
	next := *instance
	next.BaselineServiceRounds = cloneBaselineServiceRounds(instance.BaselineServiceRounds)
	if err := mutate(&next); err != nil {
		return nil, err
	}
	materializePlanes(&next)
	if err := saveRuntimeConfig(&next); err != nil {
		return nil, err
	}
	next.BaselineServiceRounds = cloneBaselineServiceRounds(next.BaselineServiceRounds)
	instance = &next
	copy := next
	copy.BaselineServiceRounds = cloneBaselineServiceRounds(next.BaselineServiceRounds)
	return &copy, nil
}

func materializePlanes(cfg *Config) {
	cfg.ControlPlane = ControlPlaneConfig{Bind: cfg.APIBind, Port: cfg.APIPort}
	if cfg.DataBindMode != "configured" && cfg.DataBindMode != "wildcard" {
		cfg.DataBindMode = "configured"
	}
	cfg.DataPlane = DataPlaneConfig{DefaultBind: cfg.TeamIP, BindMode: cfg.DataBindMode}
}

func normalizeDefaults(cfg *Config) {
	if cfg.TeamPassword == "" {
		cfg.TeamPassword = "changeme"
	}
	if cfg.FlagIDPollInterval <= 0 {
		cfg.FlagIDPollInterval = 5
	}
	if cfg.RoundDurationSec <= 0 {
		cfg.RoundDurationSec = 120
	}
	if cfg.KeepRounds <= 0 {
		cfg.KeepRounds = 5
	}
	if cfg.BaselineStartRound <= 0 || cfg.BaselineStartRound >= 10000 {
		cfg.BaselineStartRound = 1
	}
	span := cfg.BaselineEndRound - cfg.BaselineStartRound + 1
	if span < 2 || span > 50 || cfg.BaselineEndRound > 10000 {
		cfg.BaselineEndRound = cfg.BaselineStartRound + 4
		if cfg.BaselineEndRound > 10000 {
			cfg.BaselineEndRound = cfg.BaselineStartRound + 1
		}
	}
	for serviceID, rounds := range cfg.BaselineServiceRounds {
		span := rounds.EndRound - rounds.StartRound + 1
		if serviceID == "" || rounds.StartRound < 1 || rounds.EndRound > 10000 || span < 2 || span > 50 {
			delete(cfg.BaselineServiceRounds, serviceID)
		}
	}
	if cfg.FlowCorrelationWindowSec <= 0 {
		cfg.FlowCorrelationWindowSec = 120
	}
	if cfg.CleanupMaxAgeMinutes < 0 {
		cfg.CleanupMaxAgeMinutes = 0
	}
	if cfg.CleanupMaxDBSizeMB < 0 {
		cfg.CleanupMaxDBSizeMB = 0
	}
	switch cfg.FlagIDFormat {
	case "cyberchallenge", "saarctf", "faustctf", "forcad", "enowars":
	default:
		cfg.FlagIDFormat = "cyberchallenge"
	}
	if cfg.TrafficMode != "live" && cfg.TrafficMode != "static" {
		cfg.TrafficMode = "live"
	}
}

func loadRuntimeConfig(cfg *Config) error {
	path := filepath.Join(cfg.DataDir, runtimeConfigName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading runtime config: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("securing runtime config: %w", err)
	}
	var saved runtimeConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	applyRuntimeConfig(cfg, saved)
	return nil
}

func applyRuntimeConfig(cfg *Config, saved runtimeConfig) {
	if saved.TeamPassword != nil {
		cfg.TeamPassword = *saved.TeamPassword
	}
	if saved.FlagRegex != nil {
		cfg.FlagRegex = *saved.FlagRegex
	}
	if saved.CleanupMaxAgeMinutes != nil {
		cfg.CleanupMaxAgeMinutes = *saved.CleanupMaxAgeMinutes
	}
	if saved.CleanupMaxDBSizeMB != nil {
		cfg.CleanupMaxDBSizeMB = *saved.CleanupMaxDBSizeMB
	}
	if saved.FlagIDEnabled != nil {
		cfg.FlagIDEnabled = *saved.FlagIDEnabled
	}
	if saved.OurTeamID != nil {
		cfg.OurTeamID = *saved.OurTeamID
	}
	if saved.FlagIDAPIURL != nil {
		cfg.FlagIDAPIURL = *saved.FlagIDAPIURL
	}
	if saved.FlagIDPollInterval != nil {
		cfg.FlagIDPollInterval = *saved.FlagIDPollInterval
	}
	if saved.FlagIDFormat != nil {
		cfg.FlagIDFormat = *saved.FlagIDFormat
	}
	if saved.RoundDurationSec != nil {
		cfg.RoundDurationSec = *saved.RoundDurationSec
	}
	if saved.CompetitionStart != nil {
		cfg.CompetitionStart = *saved.CompetitionStart
	}
	if saved.KeepRounds != nil {
		cfg.KeepRounds = *saved.KeepRounds
	}
	if saved.BaselineStartRound != nil {
		cfg.BaselineStartRound = *saved.BaselineStartRound
	}
	if saved.BaselineEndRound != nil {
		cfg.BaselineEndRound = *saved.BaselineEndRound
	}
	if saved.BaselineServiceRounds != nil {
		cfg.BaselineServiceRounds = cloneBaselineServiceRounds(saved.BaselineServiceRounds)
	}
	if saved.TrafficMode != nil {
		cfg.TrafficMode = *saved.TrafficMode
	}
	if saved.FlowCorrelationWindowSec != nil {
		cfg.FlowCorrelationWindowSec = *saved.FlowCorrelationWindowSec
	}
	if saved.PcapExportDir != nil {
		cfg.PcapExportDir = *saved.PcapExportDir
	}
	if saved.PcapAutoSave != nil {
		cfg.PcapAutoSave = *saved.PcapAutoSave
	}
}

func saveRuntimeConfig(cfg *Config) error {
	saved := runtimeConfig{
		TeamPassword: &cfg.TeamPassword, FlagRegex: &cfg.FlagRegex,
		CleanupMaxAgeMinutes: &cfg.CleanupMaxAgeMinutes, CleanupMaxDBSizeMB: &cfg.CleanupMaxDBSizeMB,
		FlagIDEnabled: &cfg.FlagIDEnabled, OurTeamID: &cfg.OurTeamID,
		FlagIDAPIURL: &cfg.FlagIDAPIURL, FlagIDPollInterval: &cfg.FlagIDPollInterval,
		FlagIDFormat: &cfg.FlagIDFormat, RoundDurationSec: &cfg.RoundDurationSec,
		CompetitionStart: &cfg.CompetitionStart, KeepRounds: &cfg.KeepRounds,
		BaselineStartRound: &cfg.BaselineStartRound, BaselineEndRound: &cfg.BaselineEndRound,
		BaselineServiceRounds: cloneBaselineServiceRounds(cfg.BaselineServiceRounds),
		TrafficMode:           &cfg.TrafficMode, FlowCorrelationWindowSec: &cfg.FlowCorrelationWindowSec,
		PcapExportDir: &cfg.PcapExportDir, PcapAutoSave: &cfg.PcapAutoSave,
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding runtime config: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("creating runtime config directory: %w", err)
	}
	tmp, err := os.CreateTemp(cfg.DataDir, ".runtime_config-*.tmp")
	if err != nil {
		return fmt.Errorf("creating runtime config: %w", err)
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("securing runtime config: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing runtime config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing runtime config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing runtime config: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(cfg.DataDir, runtimeConfigName)); err != nil {
		return fmt.Errorf("publishing runtime config: %w", err)
	}
	removeTemp = false
	if dir, err := os.Open(cfg.DataDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func cloneBaselineServiceRounds(source map[string]BaselineRoundRange) map[string]BaselineRoundRange {
	copy := make(map[string]BaselineRoundRange, len(source))
	for serviceID, rounds := range source {
		copy[serviceID] = rounds
	}
	return copy
}

// boolVal parses a truthy env value ("true"/"1"/"yes"/"on", case-insensitive).
func boolVal(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		env[key] = value
	}
	return env, scanner.Err()
}
