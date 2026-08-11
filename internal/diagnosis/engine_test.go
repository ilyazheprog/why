package diagnosis

import (
	"testing"
	"whytool.org/why/internal/model"
)

func TestBindAddressInUse(t *testing.T) {
	d := Evaluate([]model.Event{{BindFailure: &model.BindFailure{PID: 42, Network: "tcp4", Address: "0.0.0.0", Port: 8080, Errno: "EADDRINUSE"}}})
	if d.Cause == nil || d.Cause.ID != "network.bind.address_in_use" || d.Confidence != model.Certain {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func TestUnknownWithoutCausalEvidence(t *testing.T) {
	d := Evaluate(nil)
	if d.Cause != nil || d.Confidence != model.Unknown {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}
