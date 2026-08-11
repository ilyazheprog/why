package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

type Config struct {
	JSON, Quiet, Suggestions bool
	Verbosity                int
	Timeout                  time.Duration
	Command                  []string
}

type verbosityValue struct{ value *int }

func (v verbosityValue) String() string   { return fmt.Sprint(*v.value) }
func (v verbosityValue) Set(string) error { (*v.value)++; return nil }
func (verbosityValue) IsBoolFlag() bool   { return true }

func Parse(args []string, stderr io.Writer) (Config, error) {
	var c Config
	c.Suggestions = true
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&c.JSON, "json", false, "write a structured JSON report")
	fs.BoolVar(&c.Quiet, "quiet", false, "suppress human diagnosis output")
	fs.BoolVar(&c.Quiet, "q", false, "suppress human diagnosis output")
	fs.DurationVar(&c.Timeout, "timeout", 0, "stop the target after this duration")
	noSuggestions := fs.Bool("no-suggestions", false, "omit remediation suggestions")
	version := fs.Bool("version", false, "print version")
	fs.Var(verbosityValue{&c.Verbosity}, "v", "increase diagnostic verbosity")
	fs.Var(verbosityValue{&c.Verbosity}, "verbose", "increase diagnostic verbosity")
	fs.BoolFunc("vv", "maximum diagnostic verbosity", func(string) error { c.Verbosity = 2; return nil })
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if *version {
		return c, errVersion
	}
	c.Suggestions = !*noSuggestions
	c.Command = fs.Args()
	if len(c.Command) == 0 {
		fs.Usage()
		return c, errors.New("missing command")
	}
	return c, nil
}

var errVersion = errors.New("version requested")

func IsVersion(err error) bool { return errors.Is(err, errVersion) }
func Usage(w io.Writer)        { fmt.Fprintln(w, "usage: why [OPTIONS] -- COMMAND [ARGS...]") }
