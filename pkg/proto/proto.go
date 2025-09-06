package proto

import "encoding/json"

// Envelope is a simple message wrapper for the WS channel.
type Envelope struct {
	Type    string          `json:"type"`    // "register" | "request" | "response" | "pong"
	Payload json.RawMessage `json:"payload"` // encoded one of the types below
}

type Register struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// Request is serialized from the public HTTP request.
type Request struct {
	TunnelID  string              `json:"tunnel_id"`
	RequestID string              `json:"request_id"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	RawQuery  string              `json:"raw_query"`
	Header    map[string][]string `json:"header"`
	Body      []byte              `json:"body"` // []byte is base64 in JSON
}

// Response is provided by the agent after hitting the local target.
type Response struct {
	TunnelID  string              `json:"tunnel_id"`
	RequestID string              `json:"request_id"`
	Status    int                 `json:"status"`
	Header    map[string][]string `json:"header"`
	Body      []byte              `json:"body"`
	Error     string              `json:"error,omitempty"`
}

// Helpers to encode/decode envelopes.
func Wrap(t string, v any) (*Envelope, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Envelope{Type: t, Payload: b}, nil
}

func Unwrap[T any](env *Envelope, out *T) error {
	return json.Unmarshal(env.Payload, out)
}
