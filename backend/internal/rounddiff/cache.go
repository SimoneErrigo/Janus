package rounddiff

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// CacheKey identifies a single computed diff. Closed rounds are immutable so
// once we have a result for (service, A, B) we can keep it indefinitely —
// the LRU bound and TTL exist purely to limit memory.
type CacheKey struct {
	ServiceID   string
	RoundA      int
	RoundB      int
	TopK        int
	IncludeDiff bool
}

// String formats the key as a stable ETag value.
func (k CacheKey) String() string {
	d := 0
	if k.IncludeDiff {
		d = 1
	}
	return fmt.Sprintf("%s|%d|%d|%d|%d", k.ServiceID, k.RoundA, k.RoundB, k.TopK, d)
}

type cacheEntry struct {
	key       CacheKey
	result    *Result
	storedAt  time.Time
	bytesSize int
}

// Cache is a small LRU + TTL cache. Safe for concurrent use.
type Cache struct {
	mu       sync.Mutex
	ll       *list.List
	idx      map[CacheKey]*list.Element
	maxItems int
	ttl      time.Duration
}

// NewCache returns a cache that holds up to maxItems entries with the given
// time-to-live per entry.
func NewCache(maxItems int, ttl time.Duration) *Cache {
	if maxItems <= 0 {
		maxItems = 64
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Cache{
		ll:       list.New(),
		idx:      make(map[CacheKey]*list.Element, maxItems),
		maxItems: maxItems,
		ttl:      ttl,
	}
}

// Get returns the cached result, or nil if absent / expired.
func (c *Cache) Get(k CacheKey) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[k]
	if !ok {
		return nil
	}
	e := el.Value.(*cacheEntry)
	if c.ttl > 0 && time.Since(e.storedAt) > c.ttl {
		c.removeElement(el)
		return nil
	}
	c.ll.MoveToFront(el)
	return e.result
}

// Put stores r under k, evicting the least-recently-used entry when full.
func (c *Cache) Put(k CacheKey, r *Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[k]; ok {
		el.Value.(*cacheEntry).result = r
		el.Value.(*cacheEntry).storedAt = time.Now()
		c.ll.MoveToFront(el)
		return
	}
	e := &cacheEntry{key: k, result: r, storedAt: time.Now()}
	el := c.ll.PushFront(e)
	c.idx[k] = el
	for c.ll.Len() > c.maxItems {
		c.removeElement(c.ll.Back())
	}
}

func (c *Cache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	e := el.Value.(*cacheEntry)
	delete(c.idx, e.key)
	c.ll.Remove(el)
}
