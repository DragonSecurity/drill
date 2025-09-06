package proto

import "encoding/json"

type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type Request struct {
	TunnelID  string              `json:"tunnel_id"`
	RequestID string              `json:"request_id"`
	Service   string              `json:"service,omitempty"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	RawQuery  string              `json:"raw_query"`
	Header    map[string][]string `json:"header"`
	Body      []byte              `json:"body"`
}
type Response struct {
	TunnelID  string              `json:"tunnel_id"`
	RequestID string              `json:"request_id"`
	Status    int                 `json:"status"`
	Header    map[string][]string `json:"header"`
	Body      []byte              `json:"body"`
	Error     string              `json:"error,omitempty"`
}

type TCPOpen struct {
	TunnelID, StreamID string `json:"tunnel_id","stream_id"`
}
type TCPData struct {
	TunnelID, StreamID string `json:"tunnel_id","stream_id"`
	Data               []byte `json:"data"`
}
type TCPClose struct {
	TunnelID, StreamID, Reason string `json:"tunnel_id","stream_id","reason"`
}

type UDPDatagram struct {
	TunnelID, Client, Direction string `json:"tunnel_id","client","direction"`
	Data                        []byte `json:"data"`
}

func Wrap(t string, v any) (*Envelope, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Envelope{Type: t, Payload: b}, nil
}
func Unwrap[T any](e *Envelope, out *T) error { return json.Unmarshal(e.Payload, out) }
