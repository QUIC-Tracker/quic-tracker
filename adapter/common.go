package adapter

import (
	"fmt"
	qt "github.com/tiferrei/quic-tracker"
	"regexp"
	"strconv"
	"strings"
)

var packetTypeToString = map[qt.PacketType]string {
	qt.VersionNegotiation: "VERNEG",
	qt.Initial: "INITIAL",
	qt.Retry: "RETRY",
	qt.Handshake: "HANDSHAKE",
	qt.ZeroRTTProtected: "ZERO",
	qt.ShortHeaderPacket: "SHORT",
}

var stringToPacketType = map[string]qt.PacketType {
	"VERNEG": qt.VersionNegotiation,
	"INITIAL": qt.Initial,
	"RETRY": qt.Retry,
	"HANDSHAKE": qt.Handshake,
	"ZERO": qt.ZeroRTTProtected,
	"SHORT": qt.ShortHeaderPacket,
}

var frameTypeToFrame = map[qt.FrameType]qt.Frame {
	qt.PaddingFrameType: new(qt.PaddingFrame),
}

type HeaderOptions struct {
	QUICVersion *uint32
}

func (ho *HeaderOptions) String() string {
	version := ""
	if ho.QUICVersion != nil {
		version = fmt.Sprintf("%#x", qt.Uint32ToBEBytes(*ho.QUICVersion))
	}
	return version
}
// INITIAL(0xff00001d)[ACK,CRYPTO]
// Is represented as:
// packetType: Initial
// headerOptions: HeaderOptions{ QUICVersion: 0xff00001d }
// frames: [ qt.AckFrame, qt.CryptoFrame ]
type AbstractSymbol struct {
	packetType qt.PacketType
	headerOptions HeaderOptions
	frameTypes []qt.FrameType
}

func (as *AbstractSymbol) String() string {
	packetType := packetTypeToString[as.packetType]
	headerOptions := as.headerOptions.String()
	var frameStrings []string
	for _, frameType := range as.frameTypes {
		frameStrings= append(frameStrings, frameType.String())
	}
	frameTypes := strings.Join(frameStrings, ",")
	return fmt.Sprintf("%v(%v)[%v]", packetType, headerOptions, frameTypes)
}

type Response []AbstractSymbol
func (as Response) String() string {
	stringSlice := make([]string, len(as))
	for index, abstractSymbol := range as {
		stringSlice[index] = abstractSymbol.String()
	}


	if len(stringSlice) == 0 {
		stringSlice = append(stringSlice, "EMPTY")
	}
	return strings.Join(stringSlice, "+")
}

func NewAbstractSymbol(packetType qt.PacketType, headerOptions HeaderOptions, frameTypes []qt.FrameType) AbstractSymbol {
	return AbstractSymbol{
		packetType:    packetType,
		headerOptions: headerOptions,
		frameTypes:    frameTypes,
	}
}

func NewAbstractSymbolFromString(message string) AbstractSymbol {
	messageStringRegex := regexp.MustCompile(`^([A-Z]+)(\(([0-9a-zx]+)\))?\[([A-Z,]+)\]$`)
	subgroups := messageStringRegex.FindStringSubmatch(message)
	// The PacketType is the second group, we can get the type with a map.
	packetType := stringToPacketType[subgroups[1]]

	// Header options contain options that might be optional, SHORT packets for example don't have QUICVersion.
	headerOptions := HeaderOptions{}
	// The fourth group has the content of header options.
	if subgroups[3] != "" {
		// We anticipate there might be more, so we split the string.
		headerOptionSlice := strings.Split(subgroups[3], ",")
		// The first option is the QUIC version.
		parsedVersion, err := strconv.ParseUint(headerOptionSlice[0][2:], 16, 32)
		if err == nil {
			version32 := uint32(parsedVersion)
			headerOptions.QUICVersion = &version32
		}
	}

	// The fifth group will be a CSV of frame types.
	frameTypes := []qt.FrameType{}
	frameSplice := strings.Split(subgroups[4], ",")
	for _, frameString := range frameSplice {
		frameTypes = append(frameTypes, qt.FrameTypeFromString(frameString))
	}

	return NewAbstractSymbol(packetType, headerOptions, frameTypes)
}
