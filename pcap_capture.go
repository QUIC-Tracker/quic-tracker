package quictracker

import (
	"fmt"
	"os/exec"
	"io/ioutil"
	"syscall"
	"time"
	"os"
	"encoding/hex"
)

func StartPcapCapture(conn *Connection, netInterface string) (*exec.Cmd, error) {
	bpfFilter := fmt.Sprintf("host %s and udp src or dst port %d", conn.Host.IP.String(), conn.Host.Port)
	var cmd *exec.Cmd
	if netInterface == "" {
		cmd = exec.Command("/usr/sbin/tcpdump", bpfFilter, "-w", "/tmp/pcap_" + hex.EncodeToString(conn.OriginalDestinationCID))
	} else {
		cmd = exec.Command("/usr/sbin/tcpdump", bpfFilter, "-i", netInterface, "-w", "/tmp/pcap_" + hex.EncodeToString(conn.OriginalDestinationCID))
	}
	err := cmd.Start()
	if err == nil {
		time.Sleep(1 * time.Second)
	}
	return cmd, err
}

func StopPcapCapture(conn *Connection, cmd *exec.Cmd) ([]byte, error) {
	time.Sleep(1 * time.Second)
	cmd.Process.Signal(syscall.SIGTERM)
	err := cmd.Wait()
	if err != nil {
		return nil, err
	}
	defer os.Remove("/tmp/pcap_" + hex.EncodeToString(conn.OriginalDestinationCID))
	return ioutil.ReadFile("/tmp/pcap_" + hex.EncodeToString(conn.OriginalDestinationCID))
}