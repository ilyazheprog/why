package diagnosis

import (
	"fmt"

	netenrich "whytool.org/why/internal/enrich/network"
	"whytool.org/why/internal/model"
)

func Evaluate(events []model.Event, process model.ProcessResult) model.Diagnosis {
	if process.Signal != "" {
		return signalDiagnosis(process)
	}
	for i := len(events) - 1; i >= 0; i-- {
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
