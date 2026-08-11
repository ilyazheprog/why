package model

import "time"

type Confidence string

const (
	Certain  Confidence = "certain"
	Likely   Confidence = "likely"
	Possible Confidence = "possible"
	Unknown  Confidence = "unknown"
)

type Command struct {
	Args []string
}

type ProcessResult struct {
	PID        int
	ExitCode   *int
	Signal     string
	Duration   time.Duration
	TimedOut   bool
	ExecFailed bool
}

type BindFailure struct {
	PID       int
	Network   string
	Address   string
	Port      uint16
	Errno     string
	Timestamp time.Time
}

type ConnectFailure struct {
	PID       int
	Network   string
	Address   string
	Port      uint16
	Errno     string
	Timestamp time.Time
}

type Event struct {
	BindFailure    *BindFailure
	ConnectFailure *ConnectFailure
}

type Evidence struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Source    string         `json:"source"`
	ProcessID int            `json:"pid,omitempty"`
	Data      map[string]any `json:"data"`
}

type Cause struct {
	ID         string     `json:"id"`
	Summary    string     `json:"summary"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence,omitempty"`
	Children   []Cause    `json:"children,omitempty"`
}

type Diagnosis struct {
	Confidence Confidence `json:"confidence"`
	Cause      *Cause     `json:"cause,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Command       []string      `json:"command"`
	Result        string        `json:"result"`
	Process       ProcessResult `json:"-"`
	Diagnosis     Diagnosis     `json:"diagnosis"`
}
