//go:build linux

package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"whytool.org/why/internal/model"
)

const unifiedRoot = "/sys/fs/cgroup"

type MemorySnapshot struct {
	Path    string
	OOM     uint64
	OOMKill uint64
	Current uint64
	Max     *uint64
	Peak    *uint64
}

func ReadMemoryForPID(pid int) (MemorySnapshot, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return MemorySnapshot{}, err
	}
	path, err := ParseUnifiedPath(string(data))
	if err != nil {
		return MemorySnapshot{}, err
	}
	return ReadMemoryPath(path)
}

func ReadMemoryPath(path string) (MemorySnapshot, error) {
	clean := filepath.Clean("/" + strings.TrimPrefix(path, "/"))
	dir := filepath.Join(unifiedRoot, clean)
	events, err := os.Open(filepath.Join(dir, "memory.events"))
	if err != nil {
		return MemorySnapshot{}, err
	}
	defer events.Close()
	snapshot := MemorySnapshot{Path: clean}
	scanner := bufio.NewScanner(events)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return MemorySnapshot{}, parseErr
		}
		switch fields[0] {
		case "oom":
			snapshot.OOM = value
		case "oom_kill":
			snapshot.OOMKill = value
		}
	}
	if err := scanner.Err(); err != nil {
		return MemorySnapshot{}, err
	}
	snapshot.Current, _ = readUint(filepath.Join(dir, "memory.current"))
	if value, readErr := readLimit(filepath.Join(dir, "memory.max")); readErr == nil {
		snapshot.Max = value
	}
	if value, readErr := readLimit(filepath.Join(dir, "memory.peak")); readErr == nil {
		snapshot.Peak = value
	}
	return snapshot, nil
}

func ParseUnifiedPath(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			if path == "" || !strings.HasPrefix(path, "/") {
				return "", errors.New("invalid cgroup v2 path")
			}
			return filepath.Clean(path), nil
		}
	}
	return "", errors.New("process is not in a cgroup v2 hierarchy")
}

func Correlate(before, after MemorySnapshot) *model.CgroupMemoryResult {
	if before.Path == "" || before.Path != after.Path {
		return nil
	}
	return &model.CgroupMemoryResult{
		Path: before.Path, OOMBefore: before.OOM, OOMAfter: after.OOM,
		OOMKillBefore: before.OOMKill, OOMKillAfter: after.OOMKill,
		CurrentBytes: after.Current, MaxBytes: after.Max, PeakBytes: after.Peak,
	}
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func readLimit(path string) (*uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	if text == "max" {
		return nil, nil
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return nil, err
	}
	return &value, nil
}
