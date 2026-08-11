//go:build linux && amd64

package linux

import (
	"fmt"
	"testing"
	"whytool.org/why/internal/model"
)

func TestRelevantEventBufferIsBounded(t *testing.T) {
	var events []model.Event
	for i := 0; i < maxRelevantEvents+20; i++ {
		events = appendRelevantEvent(events, model.Event{FileFailure: &model.FileFailure{Path: fmt.Sprint(i)}})
	}
	if len(events) != maxRelevantEvents {
		t.Fatalf("event count = %d", len(events))
	}
	if events[0].FileFailure.Path != "20" {
		t.Fatalf("oldest retained event = %q", events[0].FileFailure.Path)
	}
}

func TestSuccessfulRetryRemovesFailure(t *testing.T) {
	failure := &model.FileFailure{PID: 1, Operation: "openat", Path: "/file", Errno: "ENOENT"}
	events := recordFileOutcome(nil, failure)
	events = recordFileOutcome(events, &model.FileFailure{PID: 1, Operation: "openat", Path: "/file"})
	if len(events) != 0 {
		t.Fatalf("events were not cleared: %#v", events)
	}
}
