package flow

// Message separates bytes required for transparent forwarding from the
// application payload inspected by rules and extensions. Metadata/Decoded are
// populated once at the transport boundary and shared by every consumer.
type Message struct {
	Wire     []byte         `json:"-"`
	Payload  []byte         `json:"payload"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Decoded  map[string]any `json:"decoded,omitempty"`
}

func NewMessage(wire []byte) Message {
	copyWire := append([]byte(nil), wire...)
	return Message{Wire: copyWire, Payload: copyWire}
}
