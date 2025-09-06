package proto

type Envelope struct {
	Type      string    `json:"type"`
	TunnelID  string    `json:"tunnel_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Service   string    `json:"service,omitempty"`
	ConnID    string    `json:"conn_id,omitempty"`
	Data      []byte    `json:"data,omitempty"`
	Request   *Request  `json:"request,omitempty"`
	Response  *Response `json:"response,omitempty"`
	Error     string    `json:"error,omitempty"`
	Register  *Register `json:"register,omitempty"`
}

type Register struct {
	ID         string            `json:"id,omitempty"`
	Tenant     string            `json:"tenant,omitempty"`
	To         string            `json:"to,omitempty"`
	WebTargets map[string]string `json:"web_targets,omitempty"`
	TCPTargets map[string]string `json:"tcp_targets,omitempty"`
	UDPTargets map[string]string `json:"udp_targets,omitempty"`
}

type Request struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	RawQuery string              `json:"raw_query"`
	Header   map[string][]string `json:"header"`
	Body     []byte              `json:"body"`
}

type Response struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
	Body   []byte              `json:"body"`
	Error  string              `json:"error,omitempty"`
}
