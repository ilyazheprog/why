package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"whytool.org/why/internal/cli"
	"whytool.org/why/internal/diagnosis"
	"whytool.org/why/internal/model"
	humanout "whytool.org/why/internal/output/human"
	jsonout "whytool.org/why/internal/output/json"
	linuxtrace "whytool.org/why/internal/trace/linux"
)

const version = "0.1.0-dev"

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
	result, err := tracer.Run(ctx, model.Command{Args: cfg.Command})
	if err != nil {
		return renderExecError(cfg, err)
	}
	report := model.Report{SchemaVersion: "1", Command: cfg.Command, Process: result.Process, Diagnosis: diagnosis.Evaluate(result.Events, result.Process)}
	if result.Process.ExitCode != nil && *result.Process.ExitCode == 0 {
		report.Result = "succeeded"
	} else {
		report.Result = "failed"
	}
	if cfg.JSON {
		if err := jsonout.Render(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, "why: writing JSON:", err)
			return 65
		}
	} else if !cfg.Quiet {
		humanout.Render(os.Stderr, report, cfg.Suggestions)
	}
	if result.Process.TimedOut {
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

func renderExecError(cfg cli.Config, err error) int {
	var ee *exec.Error
	var pe *os.PathError
	if errors.As(err, &ee) || (errors.As(err, &pe) && errors.Is(err, syscall.ENOENT)) {
		fmt.Fprintf(os.Stderr, "why: command not found: %s\n", cfg.Command[0])
		return 1
	}
	if errors.Is(err, syscall.EACCES) {
		fmt.Fprintf(os.Stderr, "why: cannot execute %s: permission denied\n", cfg.Command[0])
		return 1
	}
	if errors.Is(err, syscall.ENOEXEC) {
		fmt.Fprintf(os.Stderr, "why: cannot execute %s: invalid executable format\n", cfg.Command[0])
		return 1
	}
	fmt.Fprintln(os.Stderr, "why: tracing failed:", err)
	return 65
}
