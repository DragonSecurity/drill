package server

import (
	"errors"
	"sync"
	"time"

	"github.com/DragonSecurity/drill/pkg/proto"
)

var ErrNoSuchTunnel = errors.New("no such tunnel")

type pendingResp struct {
	ch   chan *proto.Response
	dead *time.Timer
}

type Tunnel struct {
	ID      string
	Conn    Conn // abstracted for testability
	mu      sync.Mutex
	pending map[string]*pendingResp // requestID -> pending
}

type Conn interface {
	ReadEnvelope() (*proto.Envelope, error)
	WriteEnvelope(*proto.Envelope) error
	Close() error
}

type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
}

func NewManager() *Manager {
	return &Manager{tunnels: make(map[string]*Tunnel)}
}

func (m *Manager) Add(t *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[t.ID] = t
}

func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tunnels, id)
}

func (m *Manager) Get(id string) (*Tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[id]
	if !ok {
		return nil, ErrNoSuchTunnel
	}
	return t, nil
}

// runReader listens for responses on a tunnel and dispatches them to the waiting callers.
func (t *Tunnel) runReader(onClose func()) {
	defer onClose()
	for {
		env, err := t.Conn.ReadEnvelope()
		if err != nil { // connection closed
			return
		}
		switch env.Type {
		case "response":
			var r proto.Response
			if err := proto.Unwrap(env, &r); err != nil {
				continue
			}
			t.mu.Lock()
			p, ok := t.pending[r.RequestID]
			if ok {
				delete(t.pending, r.RequestID)
				t.mu.Unlock()
				p.dead.Stop()
				p.ch <- &r
				close(p.ch)
			} else {
				t.mu.Unlock()
			}
		default:
			// ignore
		}
	}
}

func (t *Tunnel) sendRequest(req *proto.Request, timeout time.Duration) (*proto.Response, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	p := &pendingResp{ch: make(chan *proto.Response, 1), dead: time.NewTimer(timeout)}

	t.mu.Lock()
	if t.pending == nil {
		t.pending = make(map[string]*pendingResp)
	}
	t.pending[req.RequestID] = p
	t.mu.Unlock()

	env, err := proto.Wrap("request", req)
	if err != nil {
		return nil, err
	}
	if err := t.Conn.WriteEnvelope(env); err != nil {
		// cleanup on write failure
		t.mu.Lock()
		delete(t.pending, req.RequestID)
		t.mu.Unlock()
		return nil, err
	}

	select {
	case r := <-p.ch:
		return r, nil
	case <-p.dead.C:
		// timeout
		t.mu.Lock()
		delete(t.pending, req.RequestID)
		t.mu.Unlock()
		return &proto.Response{TunnelID: req.TunnelID, RequestID: req.RequestID, Status: 504, Error: "agent timeout"}, nil
	}
}
