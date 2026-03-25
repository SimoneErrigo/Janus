package dropper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// RuleStore provides thread-safe access to drop rules stored in a JSON file.
type RuleStore struct {
	mu       sync.RWMutex
	filePath string
	rules    map[string]*Rule // rule ID -> rule
}

// NewRuleStore creates a new RuleStore that persists to the given data directory.
func NewRuleStore(dataDir string) (*RuleStore, error) {
	s := &RuleStore{
		filePath: filepath.Join(dataDir, "rules.json"),
		rules:    make(map[string]*Rule),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// ListRules returns all rules, optionally filtered by service ID, sorted by priority.
func (s *RuleStore) ListRules(serviceID string) []*Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*Rule
	for _, r := range s.rules {
		if serviceID == "" || r.ServiceID == serviceID {
			cp := *r
			list = append(list, &cp)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Priority < list[j].Priority
	})
	return list
}

// GetRule returns a rule by ID.
func (s *RuleStore) GetRule(id string) (*Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// CreateRule adds a new rule and persists the change.
func (s *RuleStore) CreateRule(r *Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[r.ID]; exists {
		return fmt.Errorf("rule with ID %q already exists", r.ID)
	}
	cp := *r
	s.rules[r.ID] = &cp
	return s.save()
}

// UpdateRule replaces an existing rule and persists the change.
func (s *RuleStore) UpdateRule(r *Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[r.ID]; !exists {
		return fmt.Errorf("rule with ID %q not found", r.ID)
	}
	cp := *r
	s.rules[r.ID] = &cp
	return s.save()
}

// DeleteRule removes a rule by ID and persists the change.
func (s *RuleStore) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[id]; !exists {
		return fmt.Errorf("rule with ID %q not found", id)
	}
	delete(s.rules, id)
	return s.save()
}

func (s *RuleStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading rules file: %w", err)
	}

	var list []*Rule
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parsing rules file: %w", err)
	}
	for _, r := range list {
		s.rules[r.ID] = r
	}
	return nil
}

func (s *RuleStore) save() error {
	list := make([]*Rule, 0, len(s.rules))
	for _, r := range s.rules {
		list = append(list, r)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling rules: %w", err)
	}
	return os.WriteFile(s.filePath, data, 0644)
}
