package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store provides thread-safe access to service configurations stored in a JSON file.
type Store struct {
	mu       sync.RWMutex
	filePath string
	services map[string]*Service
}

// NewStore creates a new Store that persists to the given file path.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	s := &Store{
		filePath: filepath.Join(dataDir, "services.json"),
		services: make(map[string]*Service),
	}

	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// ListServices returns all configured services.
func (s *Store) ListServices() []*Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*Service, 0, len(s.services))
	for _, svc := range s.services {
		cp := *svc
		list = append(list, &cp)
	}
	return list
}

// GetService returns a service by ID.
func (s *Store) GetService(id string) (*Service, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svc, ok := s.services[id]
	if !ok {
		return nil, false
	}
	cp := *svc
	return &cp, true
}

// CreateService adds a new service and persists the change.
func (s *Store) CreateService(svc *Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[svc.ID]; exists {
		return fmt.Errorf("service with ID %q already exists", svc.ID)
	}

	cp := *svc
	s.services[svc.ID] = &cp
	return s.save()
}

// UpdateService replaces an existing service and persists the change.
func (s *Store) UpdateService(svc *Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[svc.ID]; !exists {
		return fmt.Errorf("service with ID %q not found", svc.ID)
	}

	cp := *svc
	s.services[svc.ID] = &cp
	return s.save()
}

// DeleteService removes a service by ID and persists the change.
func (s *Store) DeleteService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[id]; !exists {
		return fmt.Errorf("service with ID %q not found", id)
	}

	delete(s.services, id)
	return s.save()
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no file yet, start empty
		}
		return fmt.Errorf("reading services file: %w", err)
	}

	var list []*Service
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parsing services file: %w", err)
	}

	for _, svc := range list {
		s.services[svc.ID] = svc
	}
	return nil
}

func (s *Store) save() error {
	list := make([]*Service, 0, len(s.services))
	for _, svc := range s.services {
		list = append(list, svc)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling services: %w", err)
	}

	if err := os.WriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("writing services file: %w", err)
	}
	return nil
}
