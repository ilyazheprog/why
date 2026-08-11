package trace

import (
	"context"

	"whytool.org/why/internal/model"
)

type Result struct {
	Process model.ProcessResult
	Events  []model.Event
}

type Tracer interface {
	Run(context.Context, model.Command) (Result, error)
}
