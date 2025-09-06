package tenancy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrTenantExists = errors.New("tenant already exists")
	ErrNoSuchTenant = errors.New("no such tenant")
)

type Tenant struct {
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Token     string    `json:"token"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	m    map[string]*Tenant
}

func NewStore(path string) *Store {
	if path == "" {
		path = "tenants.json"
	}
	return &Store{path: path, m: make(map[string]*Tenant)}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var mm map[string]*Tenant
	if err := json.Unmarshal(b, &mm); err != nil {
		return err
	}
	s.m = mm
	return nil
}

// Save snapshots the current map and writes without holding the write lock.
func (s *Store) Save() error {
	s.mu.RLock()
	data := make(map[string]*Tenant, len(s.m))
	for k, v := range s.m {
		cp := *v
		data[k] = &cp
	}
	path := s.path
	s.mu.RUnlock()

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) List() []*Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Tenant, 0, len(s.m))
	for _, t := range s.m {
		out = append(out, t)
	}
	return out
}

func slugify(sname string) string {
	s := strings.ToLower(sname)
	repl := func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}
	return strings.Trim(strings.Map(repl, s), "-")
}

func (s *Store) Create(name, token string) (*Tenant, error) {
	slug := slugify(name)
	if slug == "" {
		return nil, errors.New("invalid tenant name")
	}
	s.mu.Lock()
	if _, ok := s.m[slug]; ok {
		s.mu.Unlock()
		return nil, ErrTenantExists
	}
	t := &Tenant{Name: name, Slug: slug, Token: token, Active: true, CreatedAt: time.Now().UTC()}
	s.m[slug] = t
	s.mu.Unlock()
	if err := s.Save(); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) Delete(slug string) error {
	s.mu.Lock()
	if _, ok := s.m[slug]; !ok {
		s.mu.Unlock()
		return ErrNoSuchTenant
	}
	delete(s.m, slug)
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Rotate(slug, token string) (*Tenant, error) {
	s.mu.Lock()
	t, ok := s.m[slug]
	if !ok {
		s.mu.Unlock()
		return nil, ErrNoSuchTenant
	}
	t.Token = token
	s.mu.Unlock()
	if err := s.Save(); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) Get(slug string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[slug]
	if !ok {
		return nil, ErrNoSuchTenant
	}
	return t, nil
}

func (s *Store) Validate(slug, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[slug]
	if !ok || !t.Active {
		return false
	}
	return strings.TrimSpace(t.Token) == strings.TrimSpace(token)
}
