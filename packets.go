package main

type Packet interface {
	shouldBeAcknowledged() bool  // Indicates whether or not the packet type should be acknowledged by the mean of sending an ack
	Encoder
}

type VersionNegotationPacket struct {
	header           LongHeader
	supportedVersion []SupportedVersion
}
type SupportedVersion uint32
func (p *VersionNegotationPacket) shouldBeAcknowledged() bool { return false }
func (p *VersionNegotationPacket) toBytes() []byte            { return nil }

type CleartextPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.4
	header         LongHeader
	integrityCheck uint64 // TODO: https://tools.ietf.org/html/draft-ietf-quic-tls-05#section-6.2
}
func (p *CleartextPacket) shouldBeAcknowledged() bool { return false } // TODO: Should they be ?
func (p *CleartextPacket) toBytes() []byte            { return nil }

type ClientInitialPacket struct {
	header       LongHeader
	streamFrames []StreamFrame
	padding      []PaddingFrame
}
func (p *ClientInitialPacket) shouldBeAcknowledged() bool { return false }
func (p *ClientInitialPacket) toBytes() []byte            { return nil }

type ServerStatelessRetryPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.4.2
}

type ServerCleartextPacket struct {
	header       LongHeader
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p *ServerCleartextPacket) shouldBeAcknowledged() bool { return false }
func (p *ServerCleartextPacket) toBytes() []byte            { return nil }

type ClientCleartextPacket struct {
	header       LongHeader
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p *ClientCleartextPacket) shouldBeAcknowledged() bool { return false }
func (p *ClientCleartextPacket) toBytes() []byte            { return nil }

type ProtectedPacket struct {
	header Header
	frames []Frame
}