//go:build linux && amd64

package linux

import (
	"fmt"
	"os"
	"testing"
	"whytool.org/why/internal/model"
)

func TestProcessIDNormalizesCurrentTask(t *testing.T) {
	if got := processID(os.Getpid()); got != os.Getpid() {
		t.Fatalf("processID=%d want %d", got, os.Getpid())
	}
}

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

func TestSuccessfulOpenRemovesFailedSearchesForSameBasename(t *testing.T) {
	events := recordFileOutcome(nil, &model.FileFailure{PID: 1, Operation: "openat", Path: "/first/libfoo.so", Errno: "ENOENT"})
	events = recordFileOutcome(events, &model.FileFailure{PID: 1, Operation: "openat", Path: "/second/libfoo.so"})
	if len(events) != 0 {
		t.Fatalf("failed library search was not cleared: %#v", events)
	}
}
