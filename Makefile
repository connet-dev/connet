.PHONY: all build test test-always

default: all

all: build test

build:
	go install -v github.com/keihaya-com/connet/cmd/... 

test:
	go test -v -cover -timeout 10s ./...

test-always:
	go test -v -cover -timeout 10s -count 1 ./...

gen:
	fd --extension ".pb.go" . --exec-batch rm {}
	protoc --proto_path=pb/ --proto_path=pbs/ --proto_path=pbc/ --go_opt=module=github.com/keihaya-com/connet --go_out=./ pb/*.proto pbs/*.proto pbc/*.proto

.PHONY: run-server run-client run-sws
run-server: all
	connet server --config examples/minimal.toml

run-client: all
	connet --config examples/minimal.toml

run-sws:
	static-web-server --port 8081 --root . --directory-listing

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update
