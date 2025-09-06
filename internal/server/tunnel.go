package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/DragonSecurity/drill/pkg/proto"
)

type wsLike interface {
	ReadEnvelope() (*proto.Envelope, error)
	WriteEnvelope(*proto.Envelope) error
	Close() error
}

type Tunnel struct {
	Tenant string
	ID     string
	Conn   wsLike

	mu    sync.Mutex
	waits map[string]chan *proto.Response // RequestID -> response

	connMu sync.Mutex

	tcpMu sync.Mutex
	tcpCh map[string]chan []byte // ConnID -> data

	closed bool
}

func (t *Tunnel) init() {
	t.mu.Lock()
	if t.waits == nil {
		t.waits = make(map[string]chan *proto.Response)
	}
	t.mu.Unlock()

	t.tcpMu.Lock()
	if t.tcpCh == nil {
		t.tcpCh = make(map[string]chan []byte)
	}
	t.tcpMu.Unlock()
}

func (t *Tunnel) runReader(onClose func()) {
	t.init()
	for {
		env, err := t.Conn.ReadEnvelope()
		if err != nil {
			onClose()
			return
		}
		switch env.Type {
		case "http_response":
			t.mu.Lock()
			ch := t.waits[env.RequestID]
			if ch != nil {
				ch <- env.Response
				close(ch)
				delete(t.waits, env.RequestID)
			}
			t.mu.Unlock()

		case "tcp_data":
			t.tcpMu.Lock()
			ch := t.tcpCh[env.ConnID]
			t.tcpMu.Unlock()
			if ch != nil {
				ch <- env.Data
			}

		case "tcp_close":
			t.tcpMu.Lock()
			ch := t.tcpCh[env.ConnID]
			delete(t.tcpCh, env.ConnID)
			t.tcpMu.Unlock()
			if ch != nil {
				close(ch)
			}
		}
	}
}

// sendRequest sends an HTTP request over the tunnel and waits for the matching http_response.
func (t *Tunnel) sendRequest(req *proto.Request, timeout time.Duration, service string) (*proto.Response, error) {
	corr := randomID() // correlation ID carried in Envelope.RequestID

	// register waiter BEFORE sending
	ch := make(chan *proto.Response, 1)
	t.mu.Lock()
	t.waits[corr] = ch
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.waits, corr)
		t.mu.Unlock()
	}()

	// Build envelope that matches your reader on both ends
	env := &proto.Envelope{
		Type:      "http_request",
		RequestID: corr,
		Service:   service, // leave empty if not routing by service
		Request:   req,
	}

	// write guarded
	t.connMu.Lock()
	err := t.Conn.WriteEnvelope(env)
	t.connMu.Unlock()
	if err != nil {
		return nil, err
	}

	// wait for the paired response
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for response %s", corr)
	}
}

func (t *Tunnel) openTCP(connID, service string) error {
	return t.Conn.WriteEnvelope(&proto.Envelope{Type: "tcp_open", ConnID: connID, Service: service})
}
func (t *Tunnel) writeTCP(connID string, data []byte) error {
	return t.Conn.WriteEnvelope(&proto.Envelope{Type: "tcp_data", ConnID: connID, Data: data})
}
func (t *Tunnel) closeTCP(connID string) error {
	return t.Conn.WriteEnvelope(&proto.Envelope{Type: "tcp_close", ConnID: connID})
}

func (t *Tunnel) newTCPChan(connID string) chan []byte {
	t.tcpMu.Lock()
	defer t.tcpMu.Unlock()
	ch := make(chan []byte, 32)
	t.tcpCh[connID] = ch
	return ch
}
