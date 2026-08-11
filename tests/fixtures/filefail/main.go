package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: filefail MODE PATH")
		os.Exit(64)
	}
	mode, path := os.Args[1], os.Args[2]
	var err error
	switch mode {
	case "open":
		for range 2 {
			_, err = syscall.Open(path, syscall.O_RDONLY, 0)
		}
	case "write":
		for range 2 {
			_, err = syscall.Open(path, syscall.O_WRONLY, 0)
		}
	case "recover":
		_, _ = syscall.Open(path, syscall.O_RDONLY, 0)
		fd, createErr := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0600)
		if createErr == nil {
			syscall.Close(fd)
		}
		os.Exit(1)
	case "emfile":
		limit := syscall.Rlimit{Cur: 16, Max: 16}
		if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err == nil {
			for {
				_, err = syscall.Open(path, syscall.O_RDONLY, 0)
				if err != nil {
					break
				}
			}
			_, err = syscall.Open(path, syscall.O_RDONLY, 0)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(64)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
