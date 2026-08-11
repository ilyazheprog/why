package json

import (
	"bytes"
	stdjson "encoding/json"
	"testing"
	"whytool.org/why/internal/model"
)

func TestStableEnvelope(t *testing.T) {
	code := 1
	r := model.Report{SchemaVersion: "1", Command: []string{"false"}, Result: "failed", Process: model.ProcessResult{PID: 12, ExitCode: &code}, Diagnosis: model.Diagnosis{Confidence: model.Unknown}}
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := stdjson.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] != "1" || got["result"] != "failed" {
		t.Fatalf("unexpected document: %s", b.String())
	}
}
