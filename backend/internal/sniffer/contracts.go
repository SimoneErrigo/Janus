package sniffer

// PacketSink is the minimal event-store port used by the data plane.
// PacketStore is the SQLite adapter.
type PacketSink interface {
	Enqueue(pkt *Packet, alerts []*Alert) error
}

var _ PacketSink = (*PacketStore)(nil)
