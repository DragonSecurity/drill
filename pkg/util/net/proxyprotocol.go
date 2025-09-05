package net

import (
	"bytes"
	"fmt"
	"net"

	pp "github.com/pires/go-proxyproto"
)

func BuildProxyProtocolHeaderStruct(srcAddr, dstAddr net.Addr, version string) *pp.Header {
	var versionByte byte
	if version == "v1" {
		versionByte = 1
	} else {
		versionByte = 2 // default to v2
	}
	return pp.HeaderProxyFromAddrs(versionByte, srcAddr, dstAddr)
}

func BuildProxyProtocolHeader(srcAddr, dstAddr net.Addr, version string) ([]byte, error) {
	h := BuildProxyProtocolHeaderStruct(srcAddr, dstAddr, version)

	// Convert header to bytes using a buffer
	var buf bytes.Buffer
	_, err := h.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write proxy protocol header: %v", err)
	}
	return buf.Bytes(), nil
}
