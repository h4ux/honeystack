package manager

import (
	"fmt"
	"log"
	"sync"

	"github.com/example/honeypot/internal/config"
	"github.com/example/honeypot/internal/eventlog"
)

type Service interface {
	Name() string
	Start() error
	Stop() error
	Port() int
	UpdateConfig(cfg config.Service)
}

type Factory func(cfg config.Service, store *eventlog.Store) (Service, error)

type Status struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Port    int    `json:"port"`
	Error   string `json:"error,omitempty"`
}

type Manager struct {
	mu       sync.Mutex
	store    *eventlog.Store
	registry map[string]Factory
	running  map[string]Service
	status   map[string]Status
}

func New(store *eventlog.Store) *Manager {
	return &Manager{
		store:    store,
		registry: map[string]Factory{},
		running:  map[string]Service{},
		status:   map[string]Status{},
	}
}

func (m *Manager) Register(name string, f Factory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry[name] = f
}

func (m *Manager) List() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.registry))
	for name := range m.registry {
		st, ok := m.status[name]
		if !ok {
			st = Status{Name: name}
		}
		out = append(out, st)
	}
	return out
}

// Sync reconciles running services with the desired config.
func (m *Manager) Sync(cfg config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, factory := range m.registry {
		svcCfg, ok := cfg.Services[name]
		if !ok {
			svcCfg = config.Service{Enabled: false}
		}
		st, running := m.running[name]
		if svcCfg.Enabled && !running {
			m.startLocked(name, factory, svcCfg)
		} else if !svcCfg.Enabled && running {
			m.stopLocked(name, st)
		} else if svcCfg.Enabled && running {
			if st.Port() != svcCfg.Port {
				m.stopLocked(name, st)
				m.startLocked(name, factory, svcCfg)
			} else {
				st.UpdateConfig(svcCfg)
			}
		}
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, svc := range m.running {
		m.stopLocked(name, svc)
	}
}

func (m *Manager) startLocked(name string, f Factory, svcCfg config.Service) {
	svc, err := f(svcCfg, m.store)
	if err != nil {
		m.status[name] = Status{Name: name, Port: svcCfg.Port, Error: err.Error()}
		m.store.Log(eventlog.Event{Service: "system", Type: "service_error", Details: map[string]any{"name": name, "error": err.Error()}})
		return
	}
	if err := svc.Start(); err != nil {
		m.status[name] = Status{Name: name, Port: svcCfg.Port, Error: err.Error()}
		m.store.Log(eventlog.Event{Service: "system", Type: "service_error", Details: map[string]any{"name": name, "error": err.Error()}})
		return
	}
	m.running[name] = svc
	m.status[name] = Status{Name: name, Running: true, Port: svcCfg.Port}
	m.store.Log(eventlog.Event{Service: "system", Type: "service_started", Details: map[string]any{"name": name, "port": svcCfg.Port}})
	log.Printf("[manager] started %s on :%d", name, svcCfg.Port)
}

func (m *Manager) stopLocked(name string, svc Service) {
	if err := svc.Stop(); err != nil {
		log.Printf("[manager] error stopping %s: %v", name, err)
	}
	delete(m.running, name)
	m.status[name] = Status{Name: name}
	m.store.Log(eventlog.Event{Service: "system", Type: "service_stopped", Details: map[string]any{"name": name}})
}

// EnsureRegistered panics if a name is expected but missing (defence in depth).
func (m *Manager) EnsureRegistered(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.registry[name]; !ok {
		return fmt.Errorf("service factory missing: %s", name)
	}
	return nil
}
