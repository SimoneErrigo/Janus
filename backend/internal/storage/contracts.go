package storage

// ServiceStore and ProtocolStore are the persistence ports used by the control
// plane. Store is the local JSON adapter; other adapters can be introduced
// without changing API handlers.
type ServiceStore interface {
	ListServices() []*Service
	GetService(string) (*Service, bool)
	CreateService(*Service) error
	UpdateService(*Service) error
	DeleteService(string) error
}

type ProtocolStore interface {
	ListProtocols() []*CustomProtocol
	GetProtocol(string) (*CustomProtocol, bool)
	CreateProtocol(*CustomProtocol) error
	UpdateProtocol(*CustomProtocol) error
	DeleteProtocol(string) error
}

type Repository interface {
	ServiceStore
	ProtocolStore
}

var _ Repository = (*Store)(nil)
