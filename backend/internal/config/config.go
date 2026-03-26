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
	VMIP             string
	NetworkInterface string
	TeamPassword     string
	FlagRegex        string
	DataDir          string
	APIPort          string

	// Cleanup settings
	CleanupMaxAgeMinutes int
	CleanupMaxDBSizeMB   int

	// Flag ID settings
	FlagIDEnabled      bool
	OurTeamID          string
	FlagIDAPIURL       string
	FlagIDPollInterval int // seconds
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
			VMIP:             "0.0.0.0",
			NetworkInterface: "eth0",
			TeamPassword:     "changeme",
			FlagRegex:        "[A-Z0-9]{31}=",
			DataDir:          "/data",
			APIPort:          "8080",
		}

		env, err := parseEnvFile(envPath)
		if err != nil {
			// .env is optional; use defaults if missing
			if !os.IsNotExist(err) {
				loadErr = fmt.Errorf("parsing .env: %w", err)
				return
			}
		}

		if v, ok := env["VM_IP"]; ok {
			cfg.VMIP = v
		}
		if v, ok := env["NETWORK_INTERFACE"]; ok {
			cfg.NetworkInterface = v
		}
		if v, ok := env["TEAM_PASSWORD"]; ok {
			cfg.TeamPassword = v
		}
		if v, ok := env["FLAG_REGEX"]; ok {
			cfg.FlagRegex = v
		}
		if v, ok := env["DATA_DIR"]; ok {
			cfg.DataDir = v
		}
		if v, ok := env["API_PORT"]; ok {
			cfg.APIPort = v
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

		// Environment variables override .env file
		if v := os.Getenv("VM_IP"); v != "" {
			cfg.VMIP = v
		}
		if v := os.Getenv("NETWORK_INTERFACE"); v != "" {
			cfg.NetworkInterface = v
		}
		if v := os.Getenv("TEAM_PASSWORD"); v != "" {
			cfg.TeamPassword = v
		}
		if v := os.Getenv("FLAG_REGEX"); v != "" {
			cfg.FlagRegex = v
		}
		if v := os.Getenv("DATA_DIR"); v != "" {
			cfg.DataDir = v
		}
		if v := os.Getenv("API_PORT"); v != "" {
			cfg.APIPort = v
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
