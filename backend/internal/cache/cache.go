package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
)

// Client wraps a Redis connection with graceful fallback.
type Client struct {
	rdb *redis.Client
	mu  sync.RWMutex
	ok  bool // tracks whether Redis is reachable
}

// New creates a Redis cache client. If addr is empty, returns a no-op client.
func New(addr, password string) *Client {
	if addr == "" {
		log.Println("[cache] Redis address not configured, caching disabled")
		return &Client{}
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})

	c := &Client{rdb: rdb}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("[cache] Redis unavailable at %s: %v (falling back to SQLite)", addr, err)
		c.ok = false
	} else {
		log.Printf("[cache] Redis connected at %s", addr)
		c.ok = true
	}

	return c
}

// Available returns true if Redis is connected.
func (c *Client) Available() bool {
	if c.rdb == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ok
}

func (c *Client) ping() bool {
	if c.rdb == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := c.rdb.Ping(ctx).Err()
	c.mu.Lock()
	c.ok = err == nil
	c.mu.Unlock()
	if err != nil {
		log.Printf("[cache] Redis ping failed: %v", err)
	}
	return err == nil
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	if c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// --- Rules cache ---

const rulesKeyPrefix = "rules:"

// SetServiceRules stores the full rule set for a service.
func (c *Client) SetServiceRules(serviceID string, rules []*dropper.Rule) {
	if !c.Available() {
		return
	}

	data, err := json.Marshal(rules)
	if err != nil {
		log.Printf("[cache] Failed to marshal rules for service %s: %v", serviceID, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := c.rdb.Set(ctx, rulesKeyPrefix+serviceID, data, 0).Err(); err != nil {
		log.Printf("[cache] Failed to set rules for service %s: %v", serviceID, err)
		c.ping()
	}
}

// GetServiceRules retrieves the cached rule set for a service.
// Returns nil, false on cache miss or error.
func (c *Client) GetServiceRules(serviceID string) ([]*dropper.Rule, bool) {
	if !c.Available() {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	data, err := c.rdb.Get(ctx, rulesKeyPrefix+serviceID).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("[cache] Failed to get rules for service %s: %v", serviceID, err)
			c.ping()
		}
		return nil, false
	}

	var rules []*dropper.Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Printf("[cache] Failed to unmarshal rules for service %s: %v", serviceID, err)
		return nil, false
	}
	return rules, true
}

// InvalidateServiceRules deletes the cached rules for a service.
func (c *Client) InvalidateServiceRules(serviceID string) {
	if !c.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := c.rdb.Del(ctx, rulesKeyPrefix+serviceID).Err(); err != nil {
		log.Printf("[cache] Failed to invalidate rules for service %s: %v", serviceID, err)
		c.ping()
	}
}

// PopulateRules loads all rules from the store into Redis, grouped by service.
func (c *Client) PopulateRules(ruleStore *dropper.RuleStore) {
	if !c.Available() {
		return
	}

	allRules := ruleStore.ListRules("")
	byService := make(map[string][]*dropper.Rule)
	for _, r := range allRules {
		byService[r.ServiceID] = append(byService[r.ServiceID], r)
	}

	for svcID, rules := range byService {
		// Sort by priority
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Priority < rules[j].Priority
		})
		c.SetServiceRules(svcID, rules)
	}
	log.Printf("[cache] Populated rules cache for %d services", len(byService))
}

// --- Packet query cache ---

const (
	pktQueryPrefix = "pkt_query:"
	pktQueryTTL    = 5 * time.Second
)

// QueryHash builds a deterministic cache key for a packet query.
func QueryHash(params map[string]string) string {
	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s=%s&", k, params[k])
	}

	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:8]) // 16-char hex
}

// SetPacketQuery caches a packet query response.
func (c *Client) SetPacketQuery(serviceID, queryHash string, data []byte) {
	if !c.Available() {
		return
	}

	key := pktQueryPrefix + serviceID + ":" + queryHash
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := c.rdb.Set(ctx, key, data, pktQueryTTL).Err(); err != nil {
		log.Printf("[cache] Failed to cache packet query: %v", err)
		c.ping()
	}
}

// GetPacketQuery retrieves a cached packet query response.
// Returns nil, false on cache miss.
func (c *Client) GetPacketQuery(serviceID, queryHash string) ([]byte, bool) {
	if !c.Available() {
		return nil, false
	}

	key := pktQueryPrefix + serviceID + ":" + queryHash
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	data, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			log.Printf("[cache] Failed to get packet query cache: %v", err)
			c.ping()
		}
		return nil, false
	}
	return data, true
}

// InvalidatePacketQueries deletes all cached packet queries for a service.
func (c *Client) InvalidatePacketQueries(serviceID string) {
	if !c.Available() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pattern := pktQueryPrefix + serviceID + ":*"
	iter := c.rdb.Scan(ctx, 0, pattern, 100).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if len(keys) > 0 {
		c.rdb.Del(ctx, keys...)
	}
}

// InvalidateAllPacketQueries deletes all cached packet queries.
func (c *Client) InvalidateAllPacketQueries() {
	if !c.Available() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pattern := pktQueryPrefix + "*"
	iter := c.rdb.Scan(ctx, 0, pattern, 500).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if len(keys) > 0 {
		c.rdb.Del(ctx, keys...)
	}
}
