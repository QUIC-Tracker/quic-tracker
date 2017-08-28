package main

type Header struct {
	*LongHeader
	*ShortHeader
}
func (h *Header) toBytes() []byte {
	return nil
}

type HeaderForm bool
const ShortHeaderForm HeaderForm = false
const LongHeaderForm HeaderForm = true

type LongHeader struct {
	headerForm   HeaderForm
	packetType   LongPacketType
	connectionId uint64
	packetNumber uint32
	version      uint32
}

type LongPacketType uint8
const VersionNegotiation	LongPacketType = 0x01
const ClientInitial			LongPacketType = 0x02
const ServerStatelessRetry	LongPacketType = 0x03
const ServerCleartext 		LongPacketType = 0x04
const ClientCleartext 		LongPacketType = 0x05
const ZeroRTTProtected 		LongPacketType = 0x06
const OneRTTProtectedKP0 	LongPacketType = 0x06
const OneRTTProtectedKP1 	LongPacketType = 0x07

type ShortHeader struct {
	headerForm 			HeaderForm
	connectionIdFlag 	bool
	keyPhase			KeyPhaseBit
	packetType 			ShortHeaderPacketType
	packetNumber        uint32
	connectionId 		uint64
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true

type ShortHeaderPacketType uint8
const OneBytePacketNumber ShortHeaderPacketType = 0x01
const TwoBytesPacketNumber ShortHeaderPacketType = 0x02
const FourBytesPacketNumber ShortHeaderPacketType = 0x03