package cache

import (
	"context"
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

	memMu     sync.RWMutex
	rulesMemo map[string][]*dropper.Rule
}

// New creates a Redis cache client. If addr is empty, returns a no-op client.
func New(addr, password string) *Client {
	if addr == "" {
		log.Println("[cache] Redis address not configured, caching disabled")
		return &Client{rulesMemo: make(map[string][]*dropper.Rule)}
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})

	c := &Client{rdb: rdb, rulesMemo: make(map[string][]*dropper.Rule)}

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
	c.memMu.Lock()
	c.rulesMemo[serviceID] = cloneRules(rules)
	c.memMu.Unlock()

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
	c.memMu.RLock()
	if rules, ok := c.rulesMemo[serviceID]; ok {
		cp := cloneRules(rules)
		c.memMu.RUnlock()
		return cp, true
	}
	c.memMu.RUnlock()

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
	c.memMu.Lock()
	c.rulesMemo[serviceID] = cloneRules(rules)
	c.memMu.Unlock()
	return rules, true
}

// InvalidateServiceRules deletes the cached rules for a service.
func (c *Client) InvalidateServiceRules(serviceID string) {
	c.memMu.Lock()
	delete(c.rulesMemo, serviceID)
	c.memMu.Unlock()

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

func cloneRules(rules []*dropper.Rule) []*dropper.Rule {
	cp := make([]*dropper.Rule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		v := *r
		cp = append(cp, &v)
	}
	return cp
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

// MemoryUsageMB returns the Redis used_memory in MB, or -1 if unavailable.
func (c *Client) MemoryUsageMB() float64 {
	if !c.Available() {
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	info, err := c.rdb.Info(ctx, "memory").Result()
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(info, "\r\n") {
		if strings.HasPrefix(line, "used_memory:") {
			val := strings.TrimPrefix(line, "used_memory:")
			var bytes float64
			fmt.Sscanf(val, "%f", &bytes)
			return bytes / 1024 / 1024
		}
	}
	return -1
}
