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
type tcpStream struct {
	id string
	w  WriteCloser
}
type tcpStreamsMap struct {
	mu sync.Mutex
	m  map[string]*tcpStream
}
type WriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

type Tunnel struct {
	Tenant  string
	ID      string
	Conn    Conn
	mu      sync.Mutex
	pending map[string]*pendingResp
	tcp     *tcpStreamsMap
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

func NewManager() *Manager         { return &Manager{tunnels: make(map[string]*Tunnel)} }
func key(tenant, id string) string { return tenant + "|" + id }
func (m *Manager) Add(t *Tunnel)   { m.mu.Lock(); m.tunnels[key(t.Tenant, t.ID)] = t; m.mu.Unlock() }
func (m *Manager) RemoveWithTenant(tenant, id string) {
	m.mu.Lock()
	delete(m.tunnels, key(tenant, id))
	m.mu.Unlock()
}
func (m *Manager) GetWithTenant(tenant, id string) (*Tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.tunnels[key(tenant, id)]; ok {
		return t, nil
	}
	return nil, ErrNoSuchTunnel
}

type TunnelInfo struct{ Tenant, ID string }

func (m *Manager) List() []TunnelInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]TunnelInfo, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		out = append(out, TunnelInfo{Tenant: t.Tenant, ID: t.ID})
	}
	return out
}

func (t *Tunnel) runReader(onClose func()) {
	defer onClose()
	for {
		env, err := t.Conn.ReadEnvelope()
		if err != nil {
			return
		}
		switch env.Type {
		case "response":
			var r proto.Response
			if proto.Unwrap(env, &r) != nil {
				continue
			}
			t.mu.Lock()
			p := t.pending[r.RequestID]
			if p != nil {
				delete(t.pending, r.RequestID)
			}
			t.mu.Unlock()
			if p != nil {
				p.dead.Stop()
				p.ch <- &r
				close(p.ch)
			}
		case "tcp_data":
			var d proto.TCPData
			if proto.Unwrap(env, &d) != nil {
				continue
			}
			st := t.getTCPStream(d.StreamID)
			if st != nil {
				_, _ = st.w.Write(d.Data)
			}
		case "tcp_close":
			var c proto.TCPClose
			if proto.Unwrap(env, &c) != nil {
				continue
			}
			st := t.getTCPStream(c.StreamID)
			if st != nil {
				_ = st.w.Close()
				t.delTCPStream(c.StreamID)
			}
		case "udp":
			// UDP replies handled elsewhere (optional)
		default:
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
		t.mu.Lock()
		delete(t.pending, req.RequestID)
		t.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-p.ch:
		return r, nil
	case <-p.dead.C:
		t.mu.Lock()
		delete(t.pending, req.RequestID)
		t.mu.Unlock()
		return &proto.Response{TunnelID: req.TunnelID, RequestID: req.RequestID, Status: 504, Error: "agent timeout"}, nil
	}
}

func (t *Tunnel) addTCPStream(id string, w WriteCloser) {
	if t.tcp == nil {
		t.tcp = &tcpStreamsMap{m: make(map[string]*tcpStream)}
	}
	t.tcp.mu.Lock()
	t.tcp.m[id] = &tcpStream{id: id, w: w}
	t.tcp.mu.Unlock()
}
func (t *Tunnel) getTCPStream(id string) *tcpStream {
	if t.tcp == nil {
		return nil
	}
	t.tcp.mu.Lock()
	defer t.tcp.mu.Unlock()
	return t.tcp.m[id]
}
func (t *Tunnel) delTCPStream(id string) {
	if t.tcp == nil {
		return
	}
	t.tcp.mu.Lock()
	delete(t.tcp.m, id)
	t.tcp.mu.Unlock()
}
