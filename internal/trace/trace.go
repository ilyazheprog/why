package trace

import (
	"context"
	"fmt"

	"whytool.org/why/internal/model"
)

type CommandStartError struct{ Err error }

func (e *CommandStartError) Error() string { return fmt.Sprintf("starting target: %v", e.Err) }
func (e *CommandStartError) Unwrap() error { return e.Err }

type Result struct {
	Process model.ProcessResult
	Events  []model.Event
}

type Tracer interface {
	Run(context.Context, model.Command) (Result, error)
}
