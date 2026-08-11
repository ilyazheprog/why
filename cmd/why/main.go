package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"whytool.org/why/internal/cli"
	"whytool.org/why/internal/diagnosis"
	"whytool.org/why/internal/model"
	humanout "whytool.org/why/internal/output/human"
	jsonout "whytool.org/why/internal/output/json"
	"whytool.org/why/internal/trace"
	linuxtrace "whytool.org/why/internal/trace/linux"
)

// version is replaced in release builds with -ldflags "-X main.version=<tag>".
var version = "0.1.0-dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	cfg, err := cli.Parse(args, os.Stderr)
	if err != nil {
		if cli.IsVersion(err) {
			fmt.Fprintln(os.Stdout, "why "+version)
			return 0
		}
		return 64
	}
	ctx := context.Background()
	cancel := func() {}
	if cfg.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
	}
	defer cancel()
	targetOut, targetErr := os.Stdout, os.Stderr
	if cfg.JSON {
		targetOut = os.Stderr
	}
	tracer := &linuxtrace.Tracer{Stdin: os.Stdin, Stdout: targetOut, Stderr: targetErr}
	started := time.Now()
	result, err := tracer.Run(ctx, model.Command{Args: cfg.Command})
	if err != nil {
		var startErr *trace.CommandStartError
		if !errors.As(err, &startErr) {
			fmt.Fprintln(os.Stderr, "why: tracing failed:", err)
			return 65
		}
		process := model.ProcessResult{Duration: time.Since(started), ExecFailed: true}
		report := model.Report{SchemaVersion: "1", Command: cfg.Command, Result: "failed", Process: process, Diagnosis: diagnosis.EvaluateExecFailure(cfg.Command, startErr.Err)}
		return renderReport(cfg, report)
	}
	if result.Process.TimedOut {
		result.Process.Timeout = cfg.Timeout
	}
	report := model.Report{SchemaVersion: "1", Command: cfg.Command, Process: result.Process, Diagnosis: diagnosis.Evaluate(result.Events, result.Process)}
	if result.Process.ExitCode != nil && *result.Process.ExitCode == 0 {
		report.Result = "succeeded"
	} else {
		report.Result = "failed"
	}
	return renderReport(cfg, report)
}

func renderReport(cfg cli.Config, report model.Report) int {
	if cfg.JSON {
		if err := jsonout.Render(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, "why: writing JSON:", err)
			return 65
		}
	} else if !cfg.Quiet {
		humanout.Render(os.Stderr, report, cfg.Suggestions)
	}
	if report.Process.TimedOut {
		return 124
	}
	if report.Result == "succeeded" {
		return 0
	}
	if report.Diagnosis.Confidence == model.Unknown {
		return 2
	}
	return 1
}
