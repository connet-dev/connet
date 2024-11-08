.PHONY: all build test

default: all

all: build test

build:
	go install -v github.com/keihaya-com/connet/cmd/... 

test:
	go test -cover -timeout 10s ./...

.PHONY: run-server run-client run-sws
run-server: all
	connet-server -debug -auth xxyxx -server-cert .direnv/localhost/cert.pem -server-key .direnv/localhost/key.pem

run-client: all
	connet -debug -auth xxyxx -listen-name sws -listen-target ":9999" -connect-name sws -connect-source ":9998" -ca-cert .direnv/minica.pem -ca-key .direnv/minica-key.pem 

run-sws:
	static-web-server --port 9999 --root . --directory-listing

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update
