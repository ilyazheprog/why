//go:build linux

package network

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"whytool.org/why/internal/model"
)

type Owner struct {
	PID  int
	Name string
}

func FindListener(f model.BindFailure) (*Owner, error) {
	files := []string{"/proc/net/tcp"}
	if f.Network == "tcp6" {
		files = []string{"/proc/net/tcp6"}
	}
	inode, err := findInode(files[0], f.Port)
	if err != nil || inode == "" {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	needle := "socket:[" + inode + "]"
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
			if err == nil && target == needle {
				nameBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
				return &Owner{PID: pid, Name: strings.TrimSpace(string(nameBytes))}, nil
			}
		}
	}
	return nil, nil
}

func findInode(path string, port uint16) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if s.Scan() {
	} // header
	wantPort := fmt.Sprintf("%04X", port)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		} // LISTEN
		parts := strings.Split(fields[1], ":")
		if len(parts) == 2 && parts[1] == wantPort {
			return fields[9], nil
		}
	}
	return "", s.Err()
}
