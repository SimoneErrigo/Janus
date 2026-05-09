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
	mu               sync.RWMutex
	filePath         string
	protocolFilePath string
	services         map[string]*Service
	protocols        map[string]*CustomProtocol
}

// NewStore creates a new Store that persists to the given file path.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	s := &Store{
		filePath:         filepath.Join(dataDir, "services.json"),
		protocolFilePath: filepath.Join(dataDir, "protocols.json"),
		services:         make(map[string]*Service),
		protocols:        make(map[string]*CustomProtocol),
	}

	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.loadProtocols(); err != nil {
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

// ListProtocols returns all defined custom decoder protocols.
func (s *Store) ListProtocols() []*CustomProtocol {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*CustomProtocol, 0, len(s.protocols))
	for _, p := range s.protocols {
		cp := *p
		list = append(list, &cp)
	}
	return list
}

// GetProtocol returns a protocol by ID. The returned pointer is a copy and
// can be mutated freely without affecting the store.
func (s *Store) GetProtocol(id string) (*CustomProtocol, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.protocols[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// CreateProtocol persists a new protocol. Caller is expected to assign a
// fresh ID (UUID) and populate CreatedAt/UpdatedAt.
func (s *Store) CreateProtocol(p *CustomProtocol) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[p.ID]; exists {
		return fmt.Errorf("protocol with ID %q already exists", p.ID)
	}
	cp := *p
	s.protocols[p.ID] = &cp
	return s.saveProtocols()
}

// UpdateProtocol replaces an existing protocol. Caller is expected to bump
// UpdatedAt.
func (s *Store) UpdateProtocol(p *CustomProtocol) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[p.ID]; !exists {
		return fmt.Errorf("protocol with ID %q not found", p.ID)
	}
	cp := *p
	s.protocols[p.ID] = &cp
	return s.saveProtocols()
}

// DeleteProtocol removes a protocol and clears the binding from any service
// that referenced it, so we never leave services pointing at a missing ID.
func (s *Store) DeleteProtocol(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[id]; !exists {
		return fmt.Errorf("protocol with ID %q not found", id)
	}
	delete(s.protocols, id)
	cleared := false
	for _, svc := range s.services {
		if svc.ProtocolID == id {
			svc.ProtocolID = ""
			cleared = true
		}
	}
	if cleared {
		if err := s.save(); err != nil {
			return err
		}
	}
	return s.saveProtocols()
}

func (s *Store) loadProtocols() error {
	data, err := os.ReadFile(s.protocolFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading protocols file: %w", err)
	}
	var list []*CustomProtocol
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parsing protocols file: %w", err)
	}
	for _, p := range list {
		s.protocols[p.ID] = p
	}
	return nil
}

func (s *Store) saveProtocols() error {
	list := make([]*CustomProtocol, 0, len(s.protocols))
	for _, p := range s.protocols {
		list = append(list, p)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling protocols: %w", err)
	}
	if err := os.WriteFile(s.protocolFilePath, data, 0644); err != nil {
		return fmt.Errorf("writing protocols file: %w", err)
	}
	return nil
}
