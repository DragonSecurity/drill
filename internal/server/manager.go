package server

import (
	"errors"
	"sync"
)

type Manager struct {
	mu sync.RWMutex
	m  map[string]map[string]*Tunnel // tenant -> id -> tunnel
}

func NewManager() *Manager { return &Manager{m: map[string]map[string]*Tunnel{}} }

func (m *Manager) Add(t *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.m[t.Tenant]; !ok {
		m.m[t.Tenant] = map[string]*Tunnel{}
	}
	m.m[t.Tenant][t.ID] = t
}
func (m *Manager) RemoveWithTenant(tenant, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mm, ok := m.m[tenant]; ok {
		delete(mm, id)
		if len(mm) == 0 {
			delete(m.m, tenant)
		}
	}
}
func (m *Manager) GetWithTenant(tenant, id string) (*Tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if mm, ok := m.m[tenant]; ok {
		if t, ok2 := mm[id]; ok2 {
			return t, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *Manager) List() []*TunnelInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*TunnelInfo{}
	for tn, mm := range m.m {
		for id := range mm {
			out = append(out, &TunnelInfo{Tenant: tn, ID: id})
		}
	}
	return out
}

type TunnelInfo struct {
	Tenant string `json:"Tenant"`
	ID     string `json:"ID"`
}
