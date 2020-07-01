package quictracker

import (
	"bytes"
	"encoding/binary"
	"github.com/mpiraux/pigotls"
)

var quicVersionSalt = []byte{  // See https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
	0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
	0x43, 0x90, 0xa8, 0x99,
}

const (
	clientInitialLabel = "client in"
	serverInitialLabel = "server in"
)

type EncryptionLevel int

const (
	EncryptionLevelNone EncryptionLevel = iota
	EncryptionLevelInitial
	EncryptionLevel0RTT
	EncryptionLevelHandshake
	EncryptionLevel1RTT
	EncryptionLevelBest         // A special flag to indicate that the best encryption level available should be used
	EncryptionLevelBestAppData  // A special flag to indicate that the best app data encryption level available should be used
)

func (eL EncryptionLevel) String() string {
	return encryptionLevelToString[eL]
}

var encryptionLevelToString = map[EncryptionLevel]string {
	EncryptionLevelNone: "None",
	EncryptionLevelInitial: "Initial",
	EncryptionLevelHandshake: "Handshake",
	EncryptionLevel0RTT: "0RTT",
	EncryptionLevel1RTT: "1RTT",
	EncryptionLevelBest: "Best",
	EncryptionLevelBestAppData: "BestAppData",
}

var EncryptionLevelToPNSpace = map[EncryptionLevel]PNSpace {
	EncryptionLevelNone: PNSpaceNoSpace,
	EncryptionLevelInitial: PNSpaceInitial,
	EncryptionLevelHandshake: PNSpaceHandshake,
	EncryptionLevel0RTT: PNSpaceAppData,
	EncryptionLevel1RTT: PNSpaceAppData,
	EncryptionLevelBest: PNSpaceNoSpace,
	EncryptionLevelBestAppData: PNSpaceAppData,
}

var EncryptionLevelToPacketType = map[EncryptionLevel]PacketType{
	EncryptionLevelInitial: Initial,
	EncryptionLevelHandshake: Handshake,
	EncryptionLevel0RTT: ZeroRTTProtected,
	EncryptionLevel1RTT: ShortHeaderPacket,
}

var packetTypeToEncryptionLevel = map[PacketType]EncryptionLevel{
	Initial: EncryptionLevelInitial,
	Retry: EncryptionLevelNone,
	Handshake: EncryptionLevelHandshake,
	ZeroRTTProtected: EncryptionLevel0RTT,
	ShortHeaderPacket: EncryptionLevel1RTT,
}

var EpochToEncryptionLevel = map[pigotls.Epoch]EncryptionLevel {
	pigotls.EpochInitial: EncryptionLevelInitial,
	pigotls.Epoch0RTT: EncryptionLevel0RTT,
	pigotls.EpochHandshake: EncryptionLevelHandshake,
	pigotls.Epoch1RTT: EncryptionLevel1RTT,
}

type DirectionalEncryptionLevel struct {
	EncryptionLevel EncryptionLevel
	Read bool
	Available bool
}

type CryptoState struct {
	Read        *pigotls.AEAD
	Write       *pigotls.AEAD
	HeaderRead  *pigotls.Cipher
	HeaderWrite *pigotls.Cipher
}

type RetryPseudoPacket struct {
	OriginalDestinationCID ConnectionID
	UnusedByte byte
	Version uint32
	DestinationCID ConnectionID
	SourceCID ConnectionID
	RetryToken []byte
}

func (r *RetryPseudoPacket) Encode() []byte {
	buf := bytes.NewBuffer(nil)
	r.OriginalDestinationCID.WriteTo(buf)
	buf.WriteByte(r.UnusedByte)
	binary.Write(buf, binary.BigEndian, &r.Version)
	r.DestinationCID.WriteTo(buf)
	r.SourceCID.WriteTo(buf)
	buf.Write(r.RetryToken)
	return buf.Bytes()
}

func (s *CryptoState) InitRead(tls *pigotls.Connection, readSecret []byte) {
	s.Read = tls.NewAEAD(readSecret, false)
	s.HeaderRead = tls.NewCipher(tls.HkdfExpandLabel(readSecret, "hp", nil, tls.AEADKeySize(), pigotls.QuicBaseLabel))
}

func (s *CryptoState) InitWrite(tls *pigotls.Connection, writeSecret []byte) {
	s.Write = tls.NewAEAD(writeSecret, true)
	s.HeaderWrite = tls.NewCipher(tls.HkdfExpandLabel(writeSecret, "hp", nil, tls.AEADKeySize(), pigotls.QuicBaseLabel))
}

func NewInitialPacketProtection(conn *Connection) *CryptoState {
	initialSecret := conn.Tls.HkdfExtract(quicVersionSalt, conn.DestinationCID)
	readSecret := conn.Tls.HkdfExpandLabel(initialSecret, serverInitialLabel, nil, conn.Tls.HashDigestSize(), pigotls.BaseLabel)
	writeSecret := conn.Tls.HkdfExpandLabel(initialSecret, clientInitialLabel, nil, conn.Tls.HashDigestSize(), pigotls.BaseLabel)
	return NewProtectedCryptoState(conn.Tls, readSecret, writeSecret)
}

func NewProtectedCryptoState(tls *pigotls.Connection, readSecret []byte, writeSecret []byte) *CryptoState {
	s := new(CryptoState)
	if len(readSecret) > 0 {
		s.InitRead(tls, readSecret)
	}
	if len(writeSecret) > 0 {
		s.InitWrite(tls, writeSecret)
	}
	return s
}

func GetPacketSample(header Header, packetBytes []byte) ([]byte, int) {
	var pnOffset int
	sampleLength := 16
	switch h := header.(type) {
	case *LongHeader:
		pnOffset = h.HeaderLength() - h.TruncatedPN().Length
	case *ShortHeader:
		pnOffset = 1 + len(h.DestinationCID)
	}

	sampleOffset := pnOffset + 4

	if sampleOffset+sampleLength > len(packetBytes) {
		paddedBytes := make([]byte, sampleOffset+sampleLength)
		copy(paddedBytes, packetBytes)
		packetBytes = paddedBytes
	}

	return packetBytes[sampleOffset:sampleOffset+sampleLength], pnOffset
}
