package event

import (
	"errors"

	"github.com/DragonSecurity/drill/pkg/msg"
)

var ErrPayloadType = errors.New("error payload type")

type Handler func(payload any) error

type StartProxyPayload struct {
	NewProxyMsg *msg.NewProxy
}

type CloseProxyPayload struct {
	CloseProxyMsg *msg.CloseProxy
}
