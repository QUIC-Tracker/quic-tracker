package masterthesis

import (
	"fmt"
	"os/exec"
	"io/ioutil"
	"syscall"
	"time"
	"os"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"encoding/binary"
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket/pcap"
)

const pcapTempPath = "/tmp/test.pcap"
const pcapDecryptTempPath = "/tmp/decrypt.pcap"

func StartPcapCapture(conn *Connection) (*exec.Cmd, error) {
	bpfFilter := fmt.Sprintf("host %s and udp src or dst port %d", conn.Host.IP.String(), conn.Host.Port)
	c := exec.Command("/usr/sbin/tcpdump", bpfFilter, "-w", pcapTempPath)
	err := c.Start()
	if err == nil {
		time.Sleep(1 * time.Second)
	}
	return c, err
}

func StopPcapCapture(c *exec.Cmd) ([]byte, error) {
	time.Sleep(1 * time.Second)
	c.Process.Signal(syscall.SIGTERM)
	c.Wait()
	return ioutil.ReadFile(pcapTempPath)
}

func DecryptPcap(trace *Trace) ([]byte, error) {
	EncryptionOverhead := 16

	handle, err := pcap.OpenOffline(pcapTempPath)
	if err != nil {
		return nil, err
	}

	f, _ := os.Create(pcapDecryptTempPath)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var i int
	blacklist := make(map[int]bool)
	for packet := range packetSource.Packets() {
		if i == len(trace.Stream) {
			break
		}

		l := packet.Layers()
		payload := l[len(l) - 1].LayerContents()

		var length int
		if binary.BigEndian.Uint32(payload[9:13]) == 0 {  // Dirty hack to detect VN
			length = len(payload)
		} else {
			length = len(payload) - EncryptionOverhead
		}

		_, tracePacket := getFirstPacketOfLen(trace.Stream, length, blacklist)
		if tracePacket == nil {
			continue
		}
		decryptedPayload := gopacket.Payload(tracePacket.Data)

		copy(payload, bytes.Repeat([]byte{0}, len(payload)))
		copy(payload, decryptedPayload)

		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		i++
	}

	return ioutil.ReadFile(pcapDecryptTempPath)
}

func getFirstPacketOfLen(packets []TracePacket, length int, blacklist map[int]bool) (int, *TracePacket) {
	for i, p := range packets {
		if blacklist[i] {
			continue
		}
		if len(p.Data) == length {
			blacklist[i] = true
			return i, &p
		} else if len(packets) -1 == len(blacklist) {
			//spew.Dump(len(p.Data), length)
			//spew.Dump(p)
		}
	}

	spew.Dump(len(packets), blacklist)

	return -1, nil
}