.PHONY: all build test

default: all

all: build test

build:
	go install -v go.connet.dev/cmd/... 

test:
	go test -cover -timeout 10s ./...

.PHONY: run
run: all
	connet-server

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update
