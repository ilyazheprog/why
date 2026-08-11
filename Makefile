.PHONY: build test

build:
	CGO_ENABLED=0 go build -buildvcs=false -o why ./cmd/why

test:
	go test ./...
