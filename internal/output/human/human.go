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
	if report.Process.ExitCode != nil {
		fmt.Fprintf(w, "\n%s exited with code %d after %s\n", name, *report.Process.ExitCode, duration)
	} else {
		fmt.Fprintf(w, "\n%s terminated by %s after %s\n", name, report.Process.Signal, duration)
	}
	if report.Diagnosis.Cause == nil {
		fmt.Fprintln(w, "\nWhy could not determine the root cause.")
		return
	}
	fmt.Fprintln(w, "\nRoot cause")
	renderCause(w, *report.Diagnosis.Cause, "")
	fmt.Fprintln(w, "\nEvidence")
	for _, e := range report.Diagnosis.Evidence {
		if e.Type == "syscall" {
			fmt.Fprintf(w, "  bind(%s:%v) → %v\n", e.Data["address"], e.Data["port"], e.Data["errno"])
		}
		if e.Type == "signal" {
			fmt.Fprintf(w, "  signal: %v\n", e.Data["signal"])
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
