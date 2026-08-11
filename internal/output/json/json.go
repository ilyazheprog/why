package json

import (
	stdjson "encoding/json"
	"io"
	"whytool.org/why/internal/model"
)

type process struct {
	PID        int    `json:"pid,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	ExecFailed bool   `json:"exec_failed,omitempty"`
}
type document struct {
	SchemaVersion string          `json:"schema_version"`
	Command       []string        `json:"command"`
	Result        string          `json:"result"`
	Process       process         `json:"process"`
	Diagnosis     model.Diagnosis `json:"diagnosis"`
}

func Render(w io.Writer, r model.Report) error {
	d := document{r.SchemaVersion, r.Command, r.Result, process{r.Process.PID, r.Process.ExitCode, r.Process.Signal, r.Process.Duration.Milliseconds(), r.Process.TimedOut, r.Process.ExecFailed}, r.Diagnosis}
	enc := stdjson.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
