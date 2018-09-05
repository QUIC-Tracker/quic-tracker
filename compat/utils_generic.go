// +build !darwin

package compat

import "syscall"

type Utils byte

func (u *Utils) SetRECVTOS(fd int) error {
	return syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTOS, 1)
}
