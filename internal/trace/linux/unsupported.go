//go:build !linux || !amd64

package linux

import (
	"context"
	"errors"
	"io"
	"whytool.org/why/internal/model"
	"whytool.org/why/internal/trace"
)

type Tracer struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
}

func (*Tracer) Run(context.Context, model.Command) (trace.Result, error) {
	return trace.Result{}, errors.New("ptrace backend currently supports linux/amd64")
}
