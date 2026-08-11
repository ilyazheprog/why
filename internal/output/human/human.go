package human

import (
	"fmt"
	"io"
	"strings"
	"whytool.org/why/internal/model"
)

func Render(w io.Writer, report model.Report, suggestions bool) {
	name := report.Command[0]
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	duration := report.Process.Duration.Round(1000000)
	if report.Result == "succeeded" {
		fmt.Fprintf(w, "\nProcess succeeded.\n\nExit code: 0\nDuration: %s\n", duration)
		return
	}
	if report.Process.TimedOut {
		fmt.Fprintf(w, "\n%s timed out after %s\n", name, duration)
	} else if report.Process.ExitCode != nil {
		fmt.Fprintf(w, "\n%s exited with code %d after %s\n", name, *report.Process.ExitCode, duration)
	} else if report.Process.ExecFailed {
		fmt.Fprintf(w, "\n%s could not be executed after %s\n", name, duration)
	} else {
		fmt.Fprintf(w, "\n%s terminated by %s after %s\n", name, report.Process.Signal, duration)
	}
	if report.Diagnosis.Cause == nil {
		fmt.Fprintln(w, "\nWhy could not determine the root cause.")
		return
	}
	heading := "Root cause"
	switch report.Diagnosis.Confidence {
	case model.Likely:
		heading = "Likely cause"
	case model.Possible:
		heading = "Possible cause"
	}
	fmt.Fprintln(w, "\n"+heading)
	renderCause(w, *report.Diagnosis.Cause, "")
	fmt.Fprintln(w, "\nEvidence")
	for _, e := range report.Diagnosis.Evidence {
		if e.Type == "syscall" {
			if path, ok := e.Data["path"]; ok {
				fmt.Fprintf(w, "  %v(%q) → %v\n", e.Data["name"], path, e.Data["errno"])
			} else {
				fmt.Fprintf(w, "  %v(%s:%v) → %v\n", e.Data["name"], e.Data["address"], e.Data["port"], e.Data["errno"])
			}
		}
		if e.Type == "signal" {
			fmt.Fprintf(w, "  signal: %v\n", e.Data["signal"])
		}
		if e.Type == "exec" {
			fmt.Fprintf(w, "  execve(%q) → %v\n", e.Data["path"], e.Data["errno"])
		}
		if e.Type == "filesystem" {
			fmt.Fprintf(w, "  stat(%q) → %v\n", e.Data["path"], e.Data["errno"])
		}
		if e.Type == "supervisor" {
			fmt.Fprintf(w, "  timeout after %vms\n", e.Data["timeout_ms"])
		}
	}
	if suggestions && report.Diagnosis.Cause.ID == "network.bind.address_in_use" {
		fmt.Fprintln(w, "\nSuggestion\n  Stop the process using this port or configure the application to use another port.")
	}
}

func renderCause(w io.Writer, c model.Cause, indent string) {
	fmt.Fprintf(w, "%s└─ %s\n", indent, c.Summary)
	for _, child := range c.Children {
		renderCause(w, child, indent+"   ")
	}
}
