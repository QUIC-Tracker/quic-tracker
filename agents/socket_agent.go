package agents

import (
	"errors"
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/compat"
	"syscall"
	"unsafe"
)

type ECNStatus int

const (
	ECNStatusNonECT ECNStatus = 0
	ECNStatusECT_1            = 1
	ECNStatusECT_0            = 2
	ECNStatusCE               = 3
)

// The SocketAgent is responsible for receiving the UDP payloads off the socket and putting them in the decryption queue.
// If configured using ConfigureECN(), it will also mark the packet as with ECN(0) and report the ECN status of
// the corresponding IP packet received.
type SocketAgent struct {
	BaseAgent
	conn              *Connection
	ecn               bool
	TotalDataReceived int
	DatagramsReceived int
	SocketStatus      Broadcaster //type: err
	ECNStatus         Broadcaster //type: ECNStatus
}

func (a *SocketAgent) Run(conn *Connection) {
	a.Init("SocketAgent", conn.OriginalDestinationCID)
	a.conn = conn
	a.SocketStatus = NewBroadcaster(10)
	a.ECNStatus = NewBroadcaster(1000)
	recChan := make(chan []byte)

	go func() {
		for {
			recBuf := make([]byte, MaxUDPPayloadSize)
			oob := make([]byte, 128) // Find a reasonable upper-bound
			i, oobn, _, _, err := conn.UdpConnection.ReadMsgUDP(recBuf, oob)

			if err != nil {
				a.Logger.Println("Closing UDP socket because of error", err.Error())
				select {
				case <-recChan:
					return
				default:
				}
				close(recChan)
				a.SocketStatus.Submit(err)
				break
			}

			if a.ecn {
				ecn, err := findECNValue(oob[:oobn])
				if err != nil {
					a.Logger.Println(err.Error())
				}
				ecn = ecn & 0x03
				a.Logger.Printf("Read ECN value %d\n", ecn)
				a.ECNStatus.Submit(ECNStatus(ecn))
			}

			a.TotalDataReceived += i
			a.DatagramsReceived += 1
			a.Logger.Printf("Received %d bytes from UDP socket\n", i)
			payload := make([]byte, i)
			copy(payload, recBuf[:i])
			select {
			case <-recChan:
				return
			default:
			}
			recChan <- payload
		}
	}()

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case p, open := <-recChan:
				if !open {
					return
				}

				conn.IncomingPayloads.Submit(p)
			case shouldRestart := <-a.close:
				if !shouldRestart {
					conn.UdpConnection.Close()
				}
				return
			}
		}
	}()
}

func (a *SocketAgent) ConfigureECN() error {
	s, err := a.conn.UdpConnection.SyscallConn()
	if err != nil {
		return err
	}
	f := func(fd uintptr) {
		var u *compat.Utils
		err = u.SetRECVTOS(int(fd))
		if err != nil {
			a.ecn = false
			a.Logger.Printf("Error when setting RECVTOS: %s\n", err.Error())
			return
		}
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 2) //INET_ECN_ECT_0  // TODO: This should actually be the responsability of the SendingAgent
		if err != nil {
			a.Logger.Printf("Error when setting TOS: %s\n", err.Error())
		}
		a.ecn = err == nil
	}
	err = s.Control(f)
	if err != nil {
		return err
	}
	if !a.ecn {
		return errors.New("could not configure ecn")
	}
	return nil
}

type cmsgHdr struct {
	cLength uint64
	cLevel int32
	cType int32
}

func findECNValue(oob []byte) (byte, error) {
	for len(oob) > 0 {
		hdr := (*cmsgHdr)(unsafe.Pointer(&oob[0]))
		if hdr.cLevel == 0 && hdr.cType == 1 {
			return oob[hdr.cLength - 1], nil
		}
		oob = oob[hdr.cLength:]
	}
	return 0, errors.New("could not find ecn control message")
}