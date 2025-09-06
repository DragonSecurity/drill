package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"

	"github.com/DragonSecurity/drill/pkg/proto"
)

type TCPBind struct{ Addr, Tenant, ID string }
type UDPBind struct{ Addr, Tenant, ID string }

type ServerDeps struct {
	ctx context.Context
	mgr *Manager
	log LoggerLike
}

func runTCPBind(s *ServerDeps, b TCPBind) error {
	ln, err := net.Listen("tcp", b.Addr)
	if err != nil {
		return err
	}
	s.log.Infof("TCP listening %s -> %s/%s", b.Addr, b.Tenant, b.ID)
	go func() { <-s.ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Errorf("tcp accept: %v", err)
			continue
		}
		go s.handleTCPConn(b.Tenant, b.ID, c)
	}
}

func (s *ServerDeps) handleTCPConn(tenant, id string, c net.Conn) {
	tun, err := s.mgr.GetWithTenant(tenant, id)
	if err != nil {
		s.log.Errorf("tcp: no agent for %s/%s", tenant, id)
		_ = c.Close()
		return
	}
	streamID := randomID()
	tun.addTCPStream(streamID, c)
	env, _ := proto.Wrap("tcp_open", &proto.TCPOpen{TunnelID: id, StreamID: streamID})
	if err := tun.Conn.WriteEnvelope(env); err != nil {
		_ = c.Close()
		return
	}
	go func() {
		reader := bufio.NewReader(c)
		buf := make([]byte, 32*1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				env, _ := proto.Wrap("tcp_data", &proto.TCPData{TunnelID: id, StreamID: streamID, Data: append([]byte(nil), buf[:n]...)})
				_ = tun.Conn.WriteEnvelope(env)
			}
			if err != nil {
				env, _ := proto.Wrap("tcp_close", &proto.TCPClose{TunnelID: id, StreamID: streamID, Reason: errString(err)})
				_ = tun.Conn.WriteEnvelope(env)
				_ = c.Close()
				return
			}
		}
	}()
}

func runUDPBind(s *ServerDeps, b UDPBind) error {
	addr, err := net.ResolveUDPAddr("udp", b.Addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.log.Infof("UDP listening %s -> %s/%s", b.Addr, b.Tenant, b.ID)
	go func() { <-s.ctx.Done(); _ = uc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, client, err := uc.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Errorf("udp read: %v", err)
			continue
		}
		s.udpForward(b.Tenant, b.ID, client.String(), append([]byte(nil), buf[:n]...))
	}
}

// helper: forward UDP datagram to agent tunnel
func (s *ServerDeps) udpForward(tenant, id, client string, data []byte) {
	tun, err := s.mgr.GetWithTenant(tenant, id)
	if err != nil {
		s.log.Errorf("udp: no agent for %s/%s", tenant, id)
		return
	}
	env, _ := proto.Wrap("udp", &proto.UDPDatagram{TunnelID: id, Client: client, Direction: "to_agent", Data: data})
	_ = tun.Conn.WriteEnvelope(env)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if err == io.EOF {
		return "eof"
	}
	return err.Error()
}
