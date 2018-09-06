package compat

import "syscall"

const IP_RECVTOS = 27

type Utils byte

func (u *Utils) SetRECVTOS(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_RECVTOS, 1)
}
