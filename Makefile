.PHONY: all build test

default: all

all: build test

build:
	go install -v github.com/keihaya-com/connet/cmd/... 

test:
	go test -cover -timeout 10s ./...

.PHONY: run-server run-client
run-server: all
	connet-server

run-client: all
	connet -auth abc -listen-name vvv -listen-target ":9999" -connect-name vvv -connect-source ":9998"

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update
