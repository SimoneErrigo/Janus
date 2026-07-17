package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		list = append(list, cloneService(svc))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
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
	return cloneService(svc), true
}

// CreateService adds a new service and persists the change.
func (s *Store) CreateService(svc *Service) error {
	if svc == nil {
		return fmt.Errorf("service is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[svc.ID]; exists {
		return fmt.Errorf("service with ID %q already exists", svc.ID)
	}

	cp := cloneService(svc)
	cp.NormalizeSpec()
	next := copyServices(s.services)
	next[svc.ID] = cp
	if err := s.saveServices(next); err != nil {
		return err
	}
	s.services = next
	return nil
}

// UpdateService replaces an existing service and persists the change.
func (s *Store) UpdateService(svc *Service) error {
	if svc == nil {
		return fmt.Errorf("service is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[svc.ID]; !exists {
		return fmt.Errorf("service with ID %q not found", svc.ID)
	}

	cp := cloneService(svc)
	cp.NormalizeSpec()
	next := copyServices(s.services)
	next[svc.ID] = cp
	if err := s.saveServices(next); err != nil {
		return err
	}
	s.services = next
	return nil
}

// DeleteService removes a service by ID and persists the change.
func (s *Store) DeleteService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[id]; !exists {
		return fmt.Errorf("service with ID %q not found", id)
	}

	next := copyServices(s.services)
	delete(next, id)
	if err := s.saveServices(next); err != nil {
		return err
	}
	s.services = next
	return nil
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

	migrated := false
	for i, svc := range list {
		if svc == nil {
			return fmt.Errorf("parsing services file: entry %d is null", i)
		}
		if svc.ID == "" {
			return fmt.Errorf("parsing services file: entry %d has an empty ID", i)
		}
		if _, exists := s.services[svc.ID]; exists {
			return fmt.Errorf("parsing services file: duplicate ID %q", svc.ID)
		}
		if svc.Migrate() {
			migrated = true
		}
		s.services[svc.ID] = svc
	}
	if migrated {
		if err := s.save(); err != nil {
			return fmt.Errorf("persisting migrated services: %w", err)
		}
	}
	return nil
}

func (s *Store) save() error {
	return s.saveServices(s.services)
}

func (s *Store) saveServices(services map[string]*Service) error {
	list := make([]*Service, 0, len(services))
	for _, svc := range services {
		list = append(list, svc)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling services: %w", err)
	}

	if err := writeAtomic(s.filePath, data, 0644); err != nil {
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
		list = append(list, cloneProtocol(p))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
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
	return cloneProtocol(p), true
}

// CreateProtocol persists a new protocol. Caller is expected to assign a
// fresh ID (UUID) and populate CreatedAt/UpdatedAt.
func (s *Store) CreateProtocol(p *CustomProtocol) error {
	if p == nil {
		return fmt.Errorf("protocol is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[p.ID]; exists {
		return fmt.Errorf("protocol with ID %q already exists", p.ID)
	}
	next := copyProtocols(s.protocols)
	next[p.ID] = cloneProtocol(p)
	if err := s.saveProtocolSet(next); err != nil {
		return err
	}
	s.protocols = next
	return nil
}

// UpdateProtocol replaces an existing protocol. Caller is expected to bump
// UpdatedAt.
func (s *Store) UpdateProtocol(p *CustomProtocol) error {
	if p == nil {
		return fmt.Errorf("protocol is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[p.ID]; !exists {
		return fmt.Errorf("protocol with ID %q not found", p.ID)
	}
	next := copyProtocols(s.protocols)
	next[p.ID] = cloneProtocol(p)
	if err := s.saveProtocolSet(next); err != nil {
		return err
	}
	s.protocols = next
	return nil
}

// DeleteProtocol removes a protocol and clears the binding from any service
// that referenced it, so we never leave services pointing at a missing ID.
func (s *Store) DeleteProtocol(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.protocols[id]; !exists {
		return fmt.Errorf("protocol with ID %q not found", id)
	}
	nextProtocols := copyProtocols(s.protocols)
	delete(nextProtocols, id)
	nextServices := copyServices(s.services)
	cleared := false
	for serviceID, svc := range nextServices {
		if svc.ProtocolID == id {
			cp := cloneService(svc)
			cp.ProtocolID = ""
			nextServices[serviceID] = cp
			cleared = true
		}
	}
	if cleared {
		// Persist the unbinding first. A crash between the two atomic renames
		// leaves an unused protocol, never a service pointing to a missing one.
		if err := s.saveServices(nextServices); err != nil {
			return err
		}
	}
	if err := s.saveProtocolSet(nextProtocols); err != nil {
		if cleared {
			if rollbackErr := s.saveServices(s.services); rollbackErr != nil {
				// The safe partial state is already durable; mirror it in memory.
				s.services = nextServices
				return fmt.Errorf("%v; restoring services: %w", err, rollbackErr)
			}
		}
		return err
	}
	s.services = nextServices
	s.protocols = nextProtocols
	return nil
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
	for i, p := range list {
		if p == nil {
			return fmt.Errorf("parsing protocols file: entry %d is null", i)
		}
		if p.ID == "" {
			return fmt.Errorf("parsing protocols file: entry %d has an empty ID", i)
		}
		if _, exists := s.protocols[p.ID]; exists {
			return fmt.Errorf("parsing protocols file: duplicate ID %q", p.ID)
		}
		s.protocols[p.ID] = p
	}
	return nil
}

func (s *Store) saveProtocols() error {
	return s.saveProtocolSet(s.protocols)
}

func (s *Store) saveProtocolSet(protocols map[string]*CustomProtocol) error {
	list := make([]*CustomProtocol, 0, len(protocols))
	for _, p := range protocols {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling protocols: %w", err)
	}
	if err := writeAtomic(s.protocolFilePath, data, 0644); err != nil {
		return fmt.Errorf("writing protocols file: %w", err)
	}
	return nil
}

func cloneService(svc *Service) *Service {
	if svc == nil {
		return nil
	}
	cp := *svc
	cp.ProtoPaths = append([]string(nil), svc.ProtoPaths...)
	return &cp
}

func copyServices(src map[string]*Service) map[string]*Service {
	dst := make(map[string]*Service, len(src))
	for id, svc := range src {
		dst[id] = svc
	}
	return dst
}

func cloneProtocol(p *CustomProtocol) *CustomProtocol {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Enums = make(map[string]map[string]string, len(p.Enums))
	for name, values := range p.Enums {
		cloned := make(map[string]string, len(values))
		for value, label := range values {
			cloned[value] = label
		}
		cp.Enums[name] = cloned
	}
	cp.Structs = make(map[string][]ProtocolField, len(p.Structs))
	for name, fields := range p.Structs {
		cp.Structs[name] = append([]ProtocolField(nil), fields...)
	}
	cp.RequestFields = append([]ProtocolField(nil), p.RequestFields...)
	cp.ResponseFields = append([]ProtocolField(nil), p.ResponseFields...)
	return &cp
}

func copyProtocols(src map[string]*CustomProtocol) map[string]*CustomProtocol {
	dst := make(map[string]*CustomProtocol, len(src))
	for id, protocol := range src {
		dst[id] = protocol
	}
	return dst
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".janus-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}
