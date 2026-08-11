package diagnosis

import (
	"fmt"
	"net"
	"strconv"

	netenrich "whytool.org/why/internal/enrich/network"
	"whytool.org/why/internal/model"
)

func Evaluate(events []model.Event, process model.ProcessResult) model.Diagnosis {
	if process.ExitCode != nil && *process.ExitCode == 0 {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	if process.Signal != "" {
		return signalDiagnosis(process)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if failure := events[i].ConnectFailure; failure != nil {
			return connectDiagnosis(*failure)
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
