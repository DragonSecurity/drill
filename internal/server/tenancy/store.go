package tenancy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	m    map[string]*Tenant // slug -> tenant
}

func NewStore(path string) *Store {
	return &Store{path: path, m: make(map[string]*Tenant)}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// create empty file
			if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
				return err
			}
			s.m = map[string]*Tenant{}
			return s.saveLocked()
		}
		return err
	}
	var arr []*Tenant
	if len(b) == 0 {
		s.m = map[string]*Tenant{}
		return nil
	}
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	s.m = make(map[string]*Tenant, len(arr))
	for _, t := range arr {
		s.m[t.Slug] = t
	}
	return nil
}

func (s *Store) saveLocked() error {
	arr := make([]*Tenant, 0, len(s.m))
	for _, t := range s.m {
		arr = append(arr, t)
	}
	b, _ := json.MarshalIndent(arr, "", "  ")
	return os.WriteFile(s.path, b, 0o640)
}

func (s *Store) List() []*Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	arr := make([]*Tenant, 0, len(s.m))
	for _, t := range s.m {
		arr = append(arr, t)
	}
	return arr
}

func (s *Store) Validate(slug, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[slug]
	return ok && t.Active && t.Token == token
}
func (s *Store) ExistsActive(slug string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[slug]
	return ok && t.Active
}

func (s *Store) Create(name, token string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slug := Slugify(name)
	if slug == "" {
		return nil, fmt.Errorf("invalid name")
	}
	if _, exists := s.m[slug]; exists {
		return nil, fmt.Errorf("tenant exists")
	}
	t := &Tenant{Slug: slug, Name: name, Token: token, Active: true}
	s.m[slug] = t
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) Rotate(slug, token string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[slug]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	t.Token = token
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) Delete(slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[slug]; !ok {
		return fmt.Errorf("not found")
	}
	delete(s.m, slug)
	return s.saveLocked()
}

// Slugify very simple
func Slugify(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case r == '-', r == '_':
			out = append(out, r)
		case r == ' ', r == '.':
			out = append(out, '-')
		}
	}
	// trim dashes
	for len(out) > 0 && (out[0] == '-' || out[0] == '_') {
		out = out[1:]
	}
	for len(out) > 0 && (out[len(out)-1] == '-' || out[len(out)-1] == '_') {
		out = out[:len(out)-1]
	}
	return string(out)
}
