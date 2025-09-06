package server

import (
	"context"
	"net"
	"sync"
)

type LoggerLike interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

type BindRegistry struct {
	ctx context.Context
	mgr *Manager
	log LoggerLike

	mu    sync.Mutex
	items map[string]*BindItem
}

type BindItem struct {
	Proto  string `json:"proto"`
	Tenant string `json:"tenant"`
	ID     string `json:"id"`
	Addr   string `json:"addr"`
	stop   func() error
}

func keyOf(proto, tenant, id, addr string) string {
	return proto + "|" + tenant + "|" + id + "|" + addr
}

func NewBindRegistry(ctx context.Context, mgr *Manager, log LoggerLike) *BindRegistry {
	return &BindRegistry{ctx: ctx, mgr: mgr, log: log, items: make(map[string]*BindItem)}
}

func (br *BindRegistry) List() []*BindItem {
	br.mu.Lock()
	defer br.mu.Unlock()
	out := make([]*BindItem, 0, len(br.items))
	for _, it := range br.items {
		out = append(out, &BindItem{Proto: it.Proto, Tenant: it.Tenant, ID: it.ID, Addr: it.Addr})
	}
	return out
}

func (br *BindRegistry) StartTCP(tenant, id, addr string) (*BindItem, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	eff := ln.Addr().String()
	ctx, cancel := context.WithCancel(br.ctx)
	go func() {
		br.log.Infof("TCP dynamic listen %s -> %s/%s", eff, tenant, id)
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				return
			}
			go (&ServerDeps{ctx: ctx, mgr: br.mgr, log: br.log}).handleTCPConn(tenant, id, c)
		}
	}()
	stop := func() error { cancel(); return ln.Close() }
	it := &BindItem{Proto: "tcp", Tenant: tenant, ID: id, Addr: eff, stop: stop}
	br.mu.Lock()
	br.items[keyOf("tcp", tenant, id, eff)] = it
	br.mu.Unlock()
	return it, nil
}

func (br *BindRegistry) StartUDP(tenant, id, addr string) (*BindItem, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	eff := uc.LocalAddr().String()
	ctx, cancel := context.WithCancel(br.ctx)
	go func() {
		br.log.Infof("UDP dynamic listen %s -> %s/%s", eff, tenant, id)
		buf := make([]byte, 65535)
		for {
			n, client, err := uc.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				return
			}
			(&ServerDeps{ctx: ctx, mgr: br.mgr, log: br.log}).udpForward(tenant, id, client.String(), append([]byte(nil), buf[:n]...))
		}
	}()
	stop := func() error { cancel(); return uc.Close() }
	it := &BindItem{Proto: "udp", Tenant: tenant, ID: id, Addr: eff, stop: stop}
	br.mu.Lock()
	br.items[keyOf("udp", tenant, id, eff)] = it
	br.mu.Unlock()
	return it, nil
}

func (br *BindRegistry) Stop(proto, tenant, id, addr string) error {
	br.mu.Lock()
	it := br.items[keyOf(proto, tenant, id, addr)]
	if it != nil {
		delete(br.items, keyOf(proto, tenant, id, addr))
	}
	br.mu.Unlock()
	if it == nil {
		return nil
	}
	return it.stop()
}
