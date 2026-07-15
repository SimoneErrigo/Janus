package dropper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// OnChangeFunc is called after a rule is created, updated, or deleted.
// It receives the service ID whose rules changed.
type OnChangeFunc func(serviceID string)

// RuleStore provides thread-safe access to drop rules stored in a JSON file.
type RuleStore struct {
	mu                sync.RWMutex
	filePath          string
	revisionsFilePath string
	rules             map[string]*Rule // rule ID -> rule
	revisions         map[string][]RuleRevision
	onChange          OnChangeFunc
	// version is bumped on every rule mutation; the engine uses it to detect
	// stale compiled bundles without scanning the rule list per packet.
	version int64
}

// Version returns the current rule-store version. Bumped after every
// successful create batch, update, or delete mutation.
func (s *RuleStore) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// NewRuleStore creates a new RuleStore that persists to the given data directory.
func NewRuleStore(dataDir string) (*RuleStore, error) {
	s := &RuleStore{
		filePath:          filepath.Join(dataDir, "rules.json"),
		revisionsFilePath: filepath.Join(dataDir, "rule_revisions.json"),
		rules:             make(map[string]*Rule),
		revisions:         make(map[string][]RuleRevision),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.loadRevisions(); err != nil {
		return nil, err
	}
	if err := s.ensureCurrentRevisions(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetOnChange registers a callback invoked after any rule mutation.
func (s *RuleStore) SetOnChange(fn OnChangeFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

func (s *RuleStore) notifyChange(serviceID string) {
	s.mu.RLock()
	fn := s.onChange
	s.mu.RUnlock()
	if fn != nil {
		fn(serviceID)
	}
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
		if list[i].Priority != list[j].Priority {
			return list[i].Priority < list[j].Priority
		}
		return list[i].Name < list[j].Name
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

// CreateRule adds one rule and persists the change.
func (s *RuleStore) CreateRule(r *Rule) error {
	return s.CreateRules([]*Rule{r})
}

// CreateRules validates and publishes a batch with one rules/revisions write.
// Invalid input or a persistence error leaves the active set unchanged.
func (s *RuleStore) CreateRules(rules []*Rule) error {
	if len(rules) == 0 {
		return nil
	}
	s.mu.Lock()
	prepared := make([]Rule, len(rules))
	ids := make(map[string]struct{}, len(rules))
	updatedAt := time.Now().Unix()
	for i, rule := range rules {
		if rule == nil {
			s.mu.Unlock()
			return fmt.Errorf("rule %d is nil", i)
		}
		if _, exists := s.rules[rule.ID]; exists {
			s.mu.Unlock()
			return fmt.Errorf("rule with ID %q already exists", rule.ID)
		}
		if _, duplicate := ids[rule.ID]; duplicate {
			s.mu.Unlock()
			return fmt.Errorf("duplicate rule ID %q in batch", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		prepared[i] = *rule
		if prepared[i].Expression == "" {
			prepared[i].Expression = DeriveExpression(&prepared[i])
		}
		if _, err := filter.Compile(prepared[i].Expression); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("invalid rule expression for %q: %w", rule.ID, err)
		}
		prepared[i].Revision = 1
		prepared[i].UpdatedAt = updatedAt
	}

	for i := range prepared {
		rule := prepared[i]
		s.rules[rule.ID] = &prepared[i]
	}
	err := s.save()
	if err != nil {
		for _, rule := range prepared {
			delete(s.rules, rule.ID)
		}
		s.mu.Unlock()
		return err
	}

	previousHistory := make(map[string][]RuleRevision, len(prepared))
	previousHistoryExists := make(map[string]bool, len(prepared))
	for _, rule := range prepared {
		previousHistory[rule.ID], previousHistoryExists[rule.ID] = s.revisions[rule.ID]
		s.revisions[rule.ID] = []RuleRevision{{Rule: rule, RecordedAt: updatedAt}}
	}
	if err = s.saveRevisionsLocked(); err != nil {
		for _, rule := range prepared {
			delete(s.rules, rule.ID)
			if previousHistoryExists[rule.ID] {
				s.revisions[rule.ID] = previousHistory[rule.ID]
			} else {
				delete(s.revisions, rule.ID)
			}
		}
		if rollbackErr := s.save(); rollbackErr != nil {
			err = fmt.Errorf("%v; restoring rules: %w", err, rollbackErr)
		}
		s.mu.Unlock()
		return err
	}

	s.version++
	affectedServices := make(map[string]struct{})
	for i, rule := range rules {
		*rule = prepared[i]
		affectedServices[rule.ServiceID] = struct{}{}
	}
	s.mu.Unlock()
	for serviceID := range affectedServices {
		s.notifyChange(serviceID)
	}
	return nil
}

// UpdateRule replaces an existing rule and persists the change.
func (s *RuleStore) UpdateRule(r *Rule) error {
	s.mu.Lock()

	previous, exists := s.rules[r.ID]
	if !exists {
		s.mu.Unlock()
		return fmt.Errorf("rule with ID %q not found", r.ID)
	}
	cp := *r
	if cp.Expression == "" {
		cp.Expression = DeriveExpression(&cp)
	}
	if _, err := filter.Compile(cp.Expression); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("invalid rule expression: %w", err)
	}
	cp.Revision = previous.Revision + 1
	if cp.Revision < 2 {
		cp.Revision = 2
	}
	cp.UpdatedAt = time.Now().Unix()
	s.rules[r.ID] = &cp
	err := s.save()
	if err != nil {
		s.rules[r.ID] = previous
	} else if err = s.appendRevisionLocked(cp); err != nil {
		// Do not leave rule_revisions.json ahead of the active rules file.
		s.rules[r.ID] = previous
		if rollbackErr := s.save(); rollbackErr != nil {
			err = fmt.Errorf("%v; restoring rules: %w", err, rollbackErr)
		}
	}
	if err == nil {
		s.version++
		*r = cp
	}
	s.mu.Unlock()
	if err == nil {
		s.notifyChange(r.ServiceID)
	}
	return err
}

// DeleteRule removes a rule by ID and persists the change.
func (s *RuleStore) DeleteRule(id string) error {
	s.mu.Lock()

	r, exists := s.rules[id]
	if !exists {
		s.mu.Unlock()
		return fmt.Errorf("rule with ID %q not found", id)
	}
	serviceID := r.ServiceID
	delete(s.rules, id)
	err := s.save()
	if err != nil {
		s.rules[id] = r
	}
	if err == nil {
		s.version++
	}
	s.mu.Unlock()
	if err == nil {
		s.notifyChange(serviceID)
	}
	return err
}

// DeleteRules removes multiple rules by ID and persists the change.
func (s *RuleStore) DeleteRules(ids []string) (int, error) {
	s.mu.Lock()

	affectedServices := map[string]bool{}
	removed := make(map[string]*Rule)
	deleted := 0
	for _, id := range ids {
		if r, exists := s.rules[id]; exists {
			affectedServices[r.ServiceID] = true
			removed[id] = r
			delete(s.rules, id)
			deleted++
		}
	}
	if deleted == 0 {
		s.mu.Unlock()
		return 0, nil
	}
	err := s.save()
	if err != nil {
		for id, rule := range removed {
			s.rules[id] = rule
		}
	}
	if err == nil {
		s.version++
	}
	s.mu.Unlock()
	if err == nil {
		for svcID := range affectedServices {
			s.notifyChange(svcID)
		}
	}
	return deleted, err
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
	migrated := false
	for i, r := range list {
		if r == nil {
			return fmt.Errorf("parsing rules file: entry %d is null", i)
		}
		if r.ID == "" {
			return fmt.Errorf("parsing rules file: entry %d has an empty ID", i)
		}
		if _, exists := s.rules[r.ID]; exists {
			return fmt.Errorf("parsing rules file: duplicate ID %q", r.ID)
		}
		// Migration: existing rules without action default to "drop"
		if r.Action == "" {
			r.Action = ActionDrop
			migrated = true
		}
		// Migration: derive Expression from legacy fields when missing.
		if r.Expression == "" {
			if expr := DeriveExpression(r); expr != "" {
				r.Expression = expr
				migrated = true
			}
		}
		if r.Revision <= 0 {
			r.Revision = 1
			r.UpdatedAt = time.Now().Unix()
			migrated = true
		}
		s.rules[r.ID] = r
	}
	if migrated {
		if err := s.save(); err != nil {
			return fmt.Errorf("persisting migrated rules: %w", err)
		}
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
	return writeFileAtomic(s.filePath, data, 0644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".janus-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *RuleStore) loadRevisions() error {
	data, err := os.ReadFile(s.revisionsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading rule revisions: %w", err)
	}
	if err := json.Unmarshal(data, &s.revisions); err != nil {
		return fmt.Errorf("parsing rule revisions: %w", err)
	}
	if s.revisions == nil {
		s.revisions = make(map[string][]RuleRevision)
	}
	return nil
}

func (s *RuleStore) saveRevisionsLocked() error {
	data, err := json.MarshalIndent(s.revisions, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling rule revisions: %w", err)
	}
	if err := writeFileAtomic(s.revisionsFilePath, data, 0600); err != nil {
		return fmt.Errorf("writing rule revisions: %w", err)
	}
	return nil
}

func (s *RuleStore) appendRevisionLocked(rule Rule) error {
	history := s.revisions[rule.ID]
	s.revisions[rule.ID] = append(history, RuleRevision{Rule: rule, RecordedAt: time.Now().Unix()})
	if err := s.saveRevisionsLocked(); err != nil {
		s.revisions[rule.ID] = history
		return err
	}
	return nil
}

func (s *RuleStore) ensureCurrentRevisions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, rule := range s.rules {
		history := s.revisions[id]
		// Revision 1 denotes a fresh incarnation. This also repairs a crash
		// between publishing rules.json and replacing stale history on recreate.
		if rule.Revision == 1 && (len(history) != 1 || history[0].Rule != *rule) {
			s.revisions[id] = []RuleRevision{{Rule: *rule, RecordedAt: time.Now().Unix()}}
			changed = true
		} else if len(history) == 0 || history[len(history)-1].Rule.Revision < rule.Revision {
			s.revisions[id] = append(history, RuleRevision{Rule: *rule, RecordedAt: time.Now().Unix()})
			changed = true
		}
	}
	if changed {
		return s.saveRevisionsLocked()
	}
	return nil
}

// ListRevisions returns immutable snapshots ordered from oldest to newest.
func (s *RuleStore) ListRevisions(id string) []RuleRevision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	history := s.revisions[id]
	return append([]RuleRevision(nil), history...)
}

// RollbackRule activates a previous snapshot as a new revision.
func (s *RuleStore) RollbackRule(id string, revision int) error {
	s.mu.RLock()
	var snapshot *Rule
	for _, item := range s.revisions[id] {
		if item.Rule.Revision == revision {
			copy := item.Rule
			snapshot = &copy
			break
		}
	}
	s.mu.RUnlock()
	if snapshot == nil {
		return fmt.Errorf("revision %d for rule %q not found", revision, id)
	}
	return s.UpdateRule(snapshot)
}
