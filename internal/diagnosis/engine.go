package diagnosis

import (
	"fmt"
	"net"
	"strconv"

	netenrich "whytool.org/why/internal/enrich/network"
	"whytool.org/why/internal/model"
)

func Evaluate(events []model.Event, process model.ProcessResult) model.Diagnosis {
	if process.TimedOut {
		return timeoutDiagnosis(process)
	}
	if process.ExitCode != nil && *process.ExitCode == 0 {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	if process.Signal != "" {
		if process.Signal == "SIGKILL" && process.CgroupMemory != nil && process.CgroupMemory.OOMKillAfter > process.CgroupMemory.OOMKillBefore {
			return cgroupOOMDiagnosis(process)
		}
		return signalDiagnosis(process)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if failure := events[i].ConnectFailure; failure != nil {
			return connectDiagnosis(*failure)
		}
		if failure := events[i].FileFailure; failure != nil && repeatedFileFailure(events, i) {
			return fileDiagnosis(*failure)
		}
		failure := events[i].BindFailure
		if failure == nil || failure.Errno != "EADDRINUSE" {
			continue
		}
		evidence := model.Evidence{ID: "e1", Type: "syscall", Source: "ptrace", ProcessID: failure.PID, Data: map[string]any{
			"name": "bind", "network": failure.Network, "address": failure.Address, "port": failure.Port, "errno": failure.Errno,
		}}
		summary := fmt.Sprintf("TCP port %d is already in use", failure.Port)
		cause := &model.Cause{ID: "network.bind.address_in_use", Summary: summary, Confidence: model.Certain, Evidence: []string{"e1"}}
		if owner, _ := netenrich.FindListener(*failure); owner != nil {
			evidence2 := model.Evidence{ID: "e2", Type: "process", Source: "procfs", ProcessID: owner.PID, Data: map[string]any{"name": owner.Name}}
			cause.Children = []model.Cause{{ID: "network.listener.owner", Summary: fmt.Sprintf("%s (PID %d)", owner.Name, owner.PID), Confidence: model.Certain, Evidence: []string{"e2"}}}
			return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: []model.Evidence{evidence, evidence2}}
		}
		return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: []model.Evidence{evidence}}
	}
	return model.Diagnosis{Confidence: model.Unknown}
}

func cgroupOOMDiagnosis(process model.ProcessResult) model.Diagnosis {
	memory := process.CgroupMemory
	data := map[string]any{
		"path": memory.Path, "oom_before": memory.OOMBefore, "oom_after": memory.OOMAfter,
		"oom_kill_before": memory.OOMKillBefore, "oom_kill_after": memory.OOMKillAfter,
		"current_bytes": memory.CurrentBytes,
	}
	if memory.MaxBytes != nil {
		data["max_bytes"] = *memory.MaxBytes
	}
	if memory.PeakBytes != nil {
		data["peak_bytes"] = *memory.PeakBytes
	}
	e1 := model.Evidence{ID: "e1", Type: "signal", Source: "ptrace", ProcessID: process.PID, Data: map[string]any{"signal": process.Signal}}
	e2 := model.Evidence{ID: "e2", Type: "cgroup_memory", Source: "cgroup", ProcessID: process.PID, Data: data}
	cause := &model.Cause{ID: "memory.cgroup_oom", Summary: "Process was likely killed after its memory cgroup reported an OOM kill", Confidence: model.Likely, Evidence: []string{"e1", "e2"}}
	return model.Diagnosis{Confidence: model.Likely, Cause: cause, Evidence: []model.Evidence{e1, e2}}
}

func timeoutDiagnosis(process model.ProcessResult) model.Diagnosis {
	summary := "Process exceeded the Why timeout"
	data := map[string]any{"duration_ms": process.Duration.Milliseconds()}
	if process.Timeout > 0 {
		summary = fmt.Sprintf("Process exceeded the %s timeout", process.Timeout)
		data["timeout_ms"] = process.Timeout.Milliseconds()
	}
	evidence := model.Evidence{ID: "e1", Type: "supervisor", Source: "supervisor", ProcessID: process.PID, Data: data}
	cause := &model.Cause{ID: "process.timeout", Summary: summary, Confidence: model.Certain, Evidence: []string{"e1"}}
	return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: []model.Evidence{evidence}}
}

func repeatedFileFailure(events []model.Event, index int) bool {
	candidate := events[index].FileFailure
	if candidate == nil {
		return false
	}
	for i := index - 1; i >= 0; i-- {
		previous := events[i].FileFailure
		if previous != nil && previous.PID == candidate.PID && previous.Operation == candidate.Operation && previous.Path == candidate.Path && previous.Errno == candidate.Errno {
			return true
		}
	}
	return false
}

func fileDiagnosis(failure model.FileFailure) model.Diagnosis {
	id := "filesystem.operation_failed"
	reason := "operation failed"
	switch failure.Errno {
	case "ENOENT":
		id, reason = "filesystem.path_missing", "path does not exist"
	case "EACCES", "EPERM":
		id, reason = "filesystem.permission_denied", "permission denied"
	case "EROFS":
		id, reason = "filesystem.read_only", "filesystem is read-only"
	case "ENOSPC":
		id, reason = "filesystem.no_space", "no filesystem space was available"
	case "EDQUOT":
		id, reason = "filesystem.quota_exceeded", "storage quota was exceeded"
	case "EMFILE":
		id, reason = "resource.file_descriptor_limit", "process file descriptor limit was reached"
	case "ENFILE":
		id, reason = "resource.system_file_limit", "system file table limit was reached"
	case "EISDIR":
		id, reason = "filesystem.path_is_directory", "path is a directory"
	case "ENOTDIR":
		id, reason = "filesystem.path_component_not_directory", "a path component is not a directory"
	}
	summary := fmt.Sprintf("%s(%s) failed: %s", failure.Operation, failure.Path, reason)
	evidence := model.Evidence{ID: "e1", Type: "syscall", Source: "ptrace", ProcessID: failure.PID, Data: map[string]any{
		"name": failure.Operation, "path": failure.Path, "flags": failure.Flags, "errno": failure.Errno,
	}}
	cause := &model.Cause{ID: id, Summary: summary, Confidence: model.Likely, Evidence: []string{"e1"}}
	return model.Diagnosis{Confidence: model.Likely, Cause: cause, Evidence: []model.Evidence{evidence}}
}

func connectDiagnosis(failure model.ConnectFailure) model.Diagnosis {
	endpoint := net.JoinHostPort(failure.Address, strconv.Itoa(int(failure.Port)))
	id := "network.connection_failed"
	summary := fmt.Sprintf("Connection to %s failed", endpoint)
	switch failure.Errno {
	case "ECONNREFUSED":
		id = "network.connection_refused"
		summary = fmt.Sprintf("Connection to %s was refused", endpoint)
	case "ETIMEDOUT":
		id = "network.connection_timeout"
		summary = fmt.Sprintf("Connection to %s timed out", endpoint)
	case "ENETUNREACH":
		id = "network.network_unreachable"
		summary = fmt.Sprintf("Network is unreachable for %s", endpoint)
	case "EHOSTUNREACH":
		id = "network.host_unreachable"
		summary = fmt.Sprintf("Host %s is unreachable", endpoint)
	case "ECONNRESET":
		id = "network.connection_reset"
		summary = fmt.Sprintf("Connection to %s was reset", endpoint)
	case "EADDRNOTAVAIL":
		id = "network.address_not_available"
		summary = "No local address was available for the connection"
	}
	evidence := model.Evidence{ID: "e1", Type: "syscall", Source: "ptrace", ProcessID: failure.PID, Data: map[string]any{
		"name": "connect", "network": failure.Network, "address": failure.Address, "port": failure.Port, "errno": failure.Errno,
	}}
	cause := &model.Cause{ID: id, Summary: summary, Confidence: model.Certain, Evidence: []string{"e1"}}
	return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: []model.Evidence{evidence}}
}

func signalDiagnosis(process model.ProcessResult) model.Diagnosis {
	id := "process.signal"
	summary := fmt.Sprintf("Process was terminated with %s", process.Signal)
	switch process.Signal {
	case "SIGSEGV":
		id = "process.sigsegv"
	case "SIGABRT":
		id = "process.sigabrt"
	case "SIGKILL":
		id = "process.sigkill"
	case "SIGTERM":
		id = "process.sigterm"
	case "SIGILL":
		id = "process.sigill"
	case "SIGFPE":
		id = "process.sigfpe"
	case "SIGBUS":
		id = "process.sigbus"
	default:
		// The observed termination is certain even when no signal-specific rule exists.
		id = "process.signal_termination"
	}
	evidence := model.Evidence{ID: "e1", Type: "signal", Source: "ptrace", ProcessID: process.PID, Data: map[string]any{"signal": process.Signal}}
	cause := &model.Cause{ID: id, Summary: summary, Confidence: model.Certain, Evidence: []string{"e1"}}
	return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: []model.Evidence{evidence}}
}
