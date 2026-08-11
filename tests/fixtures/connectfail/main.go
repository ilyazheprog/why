package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: connectfail host:port")
		os.Exit(64)
	}
	host, portText, err := net.SplitHostPort(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(64)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() {
		fmt.Fprintln(os.Stderr, "IPv4 address required")
		os.Exit(64)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(64)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer syscall.Close(fd)
	sockaddr := &syscall.SockaddrInet4{Port: port, Addr: address.As4()}
	err = syscall.Connect(fd, sockaddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if os.Getenv("WHY_FIXTURE_RECOVER") != "" {
			return
		}
		os.Exit(1)
	}
}
