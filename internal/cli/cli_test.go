package cli

import (
	"io"
	"testing"
	"time"
)

func TestParseCommandAndOptions(t *testing.T) {
	c, err := Parse([]string{"--json", "-vv", "--timeout", "2s", "--", "echo", "$HOME"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.JSON || c.Verbosity != 2 || c.Timeout != 2*time.Second {
		t.Fatalf("unexpected config: %#v", c)
	}
	if len(c.Command) != 2 || c.Command[1] != "$HOME" {
		t.Fatalf("shell-like argument changed: %#v", c.Command)
	}
}
