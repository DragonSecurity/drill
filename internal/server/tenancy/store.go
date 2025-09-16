package tenancy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Tenant struct {
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Token  string `json:"token"`
	Active bool   `json:"active"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	m    map[string]*Tenant // by slug
}

func NewStore(path string) *Store { return &Store{path: path, m: map[string]*Tenant{}} }

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return errors.New("tenancy: empty storage path")
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
				return err
			}
			return os.WriteFile(s.path, []byte("[]"), 0o644)
		}
		return err
	}
	var arr []*Tenant
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	s.m = make(map[string]*Tenant, len(arr))
	for _, t := range arr {
		s.m[t.Slug] = t
	}
	return nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	arr := make([]*Tenant, 0, len(s.m))
	for _, t := range s.m {
		arr = append(arr, t)
	}
	s.mu.RUnlock()
	b, _ := json.MarshalIndent(arr, "", "  ")
	return os.WriteFile(s.path, b, 0o644)
}

func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	return s
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

func (s *Store) ExistsActive(slug string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.m[slug]
	return t != nil && t.Active
}

func (s *Store) Validate(slug, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.m[slug]
	return t != nil && t.Active && strings.TrimSpace(t.Token) == strings.TrimSpace(token)
}

func (s *Store) Create(name, token string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slug := slugify(name)
	if slug == "" {
		return nil, errors.New("invalid name")
	}
	if _, ok := s.m[slug]; ok {
		return nil, errors.New("exists")
	}
	t := &Tenant{Slug: slug, Name: name, Token: token, Active: true}
	s.m[slug] = t
	_ = s.Save()
	return t, nil
}

func (s *Store) Rotate(slug, token string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.m[slug]
	if t == nil {
		return nil, errors.New("not found")
	}
	t.Token = token
	_ = s.Save()
	return t, nil
}

func (s *Store) Delete(slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[slug]; !ok {
		return errors.New("not found")
	}
	delete(s.m, slug)
	return s.Save()
}
