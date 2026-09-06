package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = unix.IFNAMSIZ
	iffTun    = unix.IFF_TUN
	iffNoPi   = unix.IFF_NO_PI
	tunsetiff = unix.TUNSETIFF
)

type ifreqFlags struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte
}

func openTUN(name string) (*os.File, string, error) {
	if len(name) >= ifnamsiz {
		return nil, "", fmt.Errorf("tun device name too long: %q (max %d)", name, ifnamsiz-1)
	}

	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", tunDevice, err)
	}

	var ifr ifreqFlags
	copy(ifr.Name[:], name)
	ifr.Flags = iffTun | iffNoPi

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(tunsetiff), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return nil, "", fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	actualName := ""
	for i, b := range ifr.Name {
		if b == 0 {
			actualName = string(ifr.Name[:i])
			break
		}
	}
	if actualName == "" {
		actualName = name
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("set nonblock: %w", err)
	}

	file := os.NewFile(uintptr(fd), tunDevice)
	return file, actualName, nil
}

func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

func isTunDevice(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/tun_flags")
	return err == nil
}
