package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

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

	// TeamIP is our team's address on the competition network. When a
	// service's listen address omits the host (e.g. ":8080" or just a port),
	// the proxy binds it to TeamIP instead of every interface.
	TeamIP string

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
	RoundDurationSec int    // duration of a single round in seconds (default 120)
	CompetitionStart string // when the competition started (RFC3339, optional)
	KeepRounds       int    // how many rounds of flagIds to keep (default 5)

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
	instance *Config
	once     sync.Once
)

// Load reads the .env file and returns the Config singleton.
func Load(envPath string) (*Config, error) {
	var loadErr error
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
			FlagIDFormat:             "cyberchallenge",
			ProtoDir:                 "/protos",
			PyFilterEnabled:          true,
		}

		env, err := parseEnvFile(envPath)
		if err != nil {
			// .env is optional; use defaults if missing
			if !os.IsNotExist(err) {
				loadErr = fmt.Errorf("parsing .env: %w", err)
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

		// Derive PcapExportDir default from DataDir if not set
		if cfg.PcapExportDir == "" {
			cfg.PcapExportDir = cfg.DataDir + "/pcap"
		}

		instance = cfg
	})

	if loadErr != nil {
		return nil, loadErr
	}
	return instance, nil
}

// Get returns the loaded Config singleton. Panics if Load was not called.
func Get() *Config {
	if instance == nil {
		panic("config.Load() must be called before config.Get()")
	}
	return instance
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
