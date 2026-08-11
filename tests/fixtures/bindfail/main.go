package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	address := "127.0.0.1:38181"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if os.Getenv("WHY_FIXTURE_HOLD") != "" {
		time.Sleep(10 * time.Second)
	}
	listener.Close()
}
