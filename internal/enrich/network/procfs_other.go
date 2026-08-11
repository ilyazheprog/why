//go:build !linux

package network

import "whytool.org/why/internal/model"

type Owner struct {
	PID  int
	Name string
}

func FindListener(model.BindFailure) (*Owner, error) { return nil, nil }
