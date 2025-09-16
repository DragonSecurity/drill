package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/DragonSecurity/drill/pkg/util"
)

type LoggerLike interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

type BindRegistry struct {
	ctx context.Context
	mgr *Manager
	log *util.Logger

	mu  sync.Mutex
	tcp map[string]*tcpBind // key: tenant|agent|id|addr
	udp map[string]*udpBind
}

func NewBindRegistry(ctx context.Context, mgr *Manager, log *util.Logger) *BindRegistry {
	return &BindRegistry{ctx: ctx, mgr: mgr, log: log, tcp: map[string]*tcpBind{}, udp: map[string]*udpBind{}}
}

type tcpBind struct {
	tenant, agent, id string
	addr              string
	ln                net.Listener
	stop              func()
}
type udpBind struct {
	tenant, agent, id string
	addr              string
	pc                net.PacketConn
	stop              func()
}

func key(parts ...string) string {
	return fmt.Sprintf("%s|%s|%s|%s", parts[0], parts[1], parts[2], parts[3])
}

type BindItem struct {
	Proto  string `json:"proto"`
	Tenant string `json:"tenant"`
	Agent  string `json:"agent"`
	ID     string `json:"id"`
	Addr   string `json:"addr"`
}

func (r *BindRegistry) List() []*BindItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*BindItem{}
	for _, b := range r.tcp {
		out = append(out, &BindItem{Proto: "tcp", Tenant: b.tenant, Agent: b.agent, ID: b.id, Addr: b.addr})
	}
	for _, b := range r.udp {
		out = append(out, &BindItem{Proto: "udp", Tenant: b.tenant, Agent: b.agent, ID: b.id, Addr: b.addr})
	}
	return out
}

func (r *BindRegistry) EnsureTCP(tenant, id, addr string) (*BindItem, error) {
	// For host-based binds we don't track agent separately; use agent=id
	return r.StartTCP(tenant, id, addr)
}
func (r *BindRegistry) EnsureUDP(tenant, id, addr string) (*BindItem, error) {
	return r.StartUDP(tenant, id, addr)
}

func (r *BindRegistry) StartTCP(tenant, id, addr string) (*BindItem, error) {
	agent := id // agent id (service name) for tcp binds
	if addr == "" {
		addr = ":0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	actual := ln.Addr().String()
	b := &tcpBind{tenant: tenant, agent: agent, id: id, addr: actual, ln: ln}
	r.mu.Lock()
	k := key(tenant, agent, id, actual)
	if _, exists := r.tcp[k]; exists {
		r.mu.Unlock()
		_ = ln.Close()
		return nil, errors.New("bind exists")
	}
	r.tcp[k] = b
	r.mu.Unlock()

	go r.serveTCP(b)
	r.log.Infof("tcp bind started %s/%s on %s", tenant, id, actual)
	return &BindItem{Proto: "tcp", Tenant: tenant, Agent: agent, ID: id, Addr: actual}, nil
}

func (r *BindRegistry) serveTCP(b *tcpBind) {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			// We treat id as service name; agent is also id for simplicity
			tun, err := r.mgr.GetWithTenant(b.tenant, b.agent)
			if err != nil {
				r.log.Errorf("tcp: no agent for %s/%s", b.tenant, b.agent)
				return
			}
			// open remote
			connID := randomID() + randomID()
			if err := tun.openTCP(connID, b.id); err != nil {
				r.log.Errorf("tcp open: %v", err)
				return
			}
			// reader from remote -> local
			dataCh := tun.newTCPChan(connID)
			done := make(chan struct{})
			go func() {
				for data := range dataCh {
					if len(data) == 0 {
						continue
					}
					if _, err := conn.Write(data); err != nil {
						break
					}
				}
				close(done)
			}()
			// local -> remote
			buf := make([]byte, 32<<10)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					_ = tun.writeTCP(connID, buf[:n])
				}
				if err != nil {
					if err != io.EOF {
						r.log.Errorf("tcp read: %v", err)
					}
					break
				}
			}
			_ = tun.closeTCP(connID)
			<-done
		}(c)
	}
}

func (r *BindRegistry) StartUDP(tenant, id, addr string) (*BindItem, error) {
	agent := id
	if addr == "" {
		addr = ":0"
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	actual := pc.LocalAddr().String()
	b := &udpBind{tenant: tenant, agent: agent, id: id, addr: actual, pc: pc}
	r.mu.Lock()
	k := key(tenant, agent, id, actual)
	if _, exists := r.udp[k]; exists {
		r.mu.Unlock()
		_ = pc.Close()
		return nil, errors.New("bind exists")
	}
	r.udp[k] = b
	r.mu.Unlock()

	go r.serveUDP(b)
	r.log.Infof("udp bind started %s/%s on %s", tenant, id, actual)
	return &BindItem{Proto: "udp", Tenant: tenant, Agent: agent, ID: id, Addr: actual}, nil
}

func (r *BindRegistry) serveUDP(b *udpBind) {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := b.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = addr
		_ = n
		// TODO: forward UDP datagram via tunnel when implemented on agent
	}
}

func (r *BindRegistry) Stop(proto, tenant, agent, id, addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(tenant, agent, id, addr)
	switch proto {
	case "tcp":
		b, ok := r.tcp[k]
		if !ok {
			return fmt.Errorf("not found")
		}
		delete(r.tcp, k)
		return b.ln.Close()
	case "udp":
		b, ok := r.udp[k]
		if !ok {
			return fmt.Errorf("not found")
		}
		delete(r.udp, k)
		return b.pc.Close()
	default:
		return fmt.Errorf("unknown proto")
	}
}

func (r *BindRegistry) StopAllFor(tenant, agent string) {
	r.mu.Lock()
	for k, b := range r.tcp {
		if b.tenant == tenant && b.agent == agent {
			_ = b.ln.Close()
			delete(r.tcp, k)
		}
	}
	for k, b := range r.udp {
		if b.tenant == tenant && b.agent == agent {
			_ = b.pc.Close()
			delete(r.udp, k)
		}
	}
	r.mu.Unlock()
}
