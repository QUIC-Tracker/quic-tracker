package masterthesis

import (
	"fmt"
	"os/exec"
	"io/ioutil"
	"syscall"
	"time"
)

const pcapTempPath = "/tmp/test.pcap"

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
	c.Process.Signal(syscall.SIGTERM)
	c.Wait()
	return ioutil.ReadFile(pcapTempPath)
}