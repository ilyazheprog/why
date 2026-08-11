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

func TestSuccessfulProcessNeverGetsFailureDiagnosis(t *testing.T) {
	code := 0
	events := []model.Event{
		{BindFailure: &model.BindFailure{PID: 42, Network: "ip4", Address: "0.0.0.0", Port: 8080, Errno: "EADDRINUSE"}},
		{ConnectFailure: &model.ConnectFailure{PID: 42, Network: "ip4", Address: "127.0.0.1", Port: 9, Errno: "ECONNREFUSED"}},
	}
	d := Evaluate(events, model.ProcessResult{ExitCode: &code})
	if d.Cause != nil || d.Confidence != model.Unknown {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func TestConnectDiagnoses(t *testing.T) {
	tests := []struct{ errno, id string }{
		{"ECONNREFUSED", "network.connection_refused"},
		{"ETIMEDOUT", "network.connection_timeout"},
		{"ENETUNREACH", "network.network_unreachable"},
		{"EHOSTUNREACH", "network.host_unreachable"},
		{"ECONNRESET", "network.connection_reset"},
		{"EADDRNOTAVAIL", "network.address_not_available"},
	}
	for _, test := range tests {
		t.Run(test.errno, func(t *testing.T) {
			events := []model.Event{{ConnectFailure: &model.ConnectFailure{PID: 42, Network: "ip4", Address: "127.0.0.1", Port: 5432, Errno: test.errno}}}
			d := Evaluate(events, model.ProcessResult{})
			if d.Cause == nil || d.Cause.ID != test.id || d.Confidence != model.Certain {
				t.Fatalf("unexpected diagnosis: %#v", d)
			}
		})
	}
}
