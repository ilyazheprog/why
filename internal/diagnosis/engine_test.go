package diagnosis

import (
	"testing"
	"whytool.org/why/internal/model"
)

func TestBindAddressInUse(t *testing.T) {
	d := Evaluate([]model.Event{{BindFailure: &model.BindFailure{PID: 42, Network: "tcp4", Address: "0.0.0.0", Port: 8080, Errno: "EADDRINUSE"}}}, model.ProcessResult{})
	if d.Cause == nil || d.Cause.ID != "network.bind.address_in_use" || d.Confidence != model.Certain {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func TestUnknownWithoutCausalEvidence(t *testing.T) {
	d := Evaluate(nil, model.ProcessResult{})
	if d.Cause != nil || d.Confidence != model.Unknown {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func TestSignalDiagnoses(t *testing.T) {
	tests := []struct{ signal, id string }{
		{"SIGSEGV", "process.sigsegv"},
		{"SIGABRT", "process.sigabrt"},
		{"SIGKILL", "process.sigkill"},
		{"SIGTERM", "process.sigterm"},
		{"SIGUSR1", "process.signal_termination"},
	}
	for _, test := range tests {
		t.Run(test.signal, func(t *testing.T) {
			d := Evaluate(nil, model.ProcessResult{PID: 42, Signal: test.signal})
			if d.Cause == nil || d.Cause.ID != test.id || d.Confidence != model.Certain {
				t.Fatalf("unexpected diagnosis: %#v", d)
			}
			if got := d.Evidence[0].Data["signal"]; got != test.signal {
				t.Fatalf("signal evidence = %v", got)
			}
		})
	}
}

func TestTerminalSignalTakesPrecedenceOverEarlierSyscallFailure(t *testing.T) {
	events := []model.Event{{BindFailure: &model.BindFailure{PID: 42, Network: "tcp4", Address: "0.0.0.0", Port: 8080, Errno: "EADDRINUSE"}}}
	d := Evaluate(events, model.ProcessResult{PID: 42, Signal: "SIGSEGV"})
	if d.Cause == nil || d.Cause.ID != "process.sigsegv" {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}
