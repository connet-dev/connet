.PHONY: all build test lint test-always

default: all

all: build test lint

build:
	go install -v github.com/connet-dev/connet/cmd/... 

test:
	go test -v -cover -timeout 10s ./...

lint:
	golangci-lint run

test-always:
	go test -v -cover -timeout 10s -count 1 ./...

test-nix:
	nix build .#checks.x86_64-linux.moduleTest

test-nix-interactive:
	nix run .#checks.x86_64-linux.moduleTest.driverInteractive

.PHONY: gen
gen:
	fd --extension ".pb.go" . --exec-batch rm {}
	protoc --proto_path=pb/ --proto_path=pbs/ --proto_path=pbc/ --proto_path=pbr/ --go_opt=module=github.com/connet-dev/connet --go_out=./ pb/*.proto pbs/*.proto pbc/*.proto pbr/*.proto

.PHONY: run-server run-client run-sws
run-server: build
	connet server --config examples/minimal.toml

run-client: build
	connet --config examples/minimal.toml

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update

.PHONY: release-clean release-build release-archive release

release-clean:
	rm -rf dist/

release-build:
	GOOS=darwin GOARCH=amd64 go build -v -o dist/build/darwin-amd64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=darwin GOARCH=arm64 go build -v -o dist/build/darwin-arm64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=linux GOARCH=amd64 go build -v -o dist/build/linux-amd64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=linux GOARCH=arm64 go build -v -o dist/build/linux-arm64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=freebsd GOARCH=amd64 go build -v -o dist/build/freebsd-amd64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=freebsd GOARCH=arm64 go build -v -o dist/build/freebsd-arm64/connet github.com/connet-dev/connet/cmd/connet
	GOOS=windows GOARCH=amd64 go build -v -o dist/build/windows-amd64/connet.exe github.com/connet-dev/connet/cmd/connet
	GOOS=windows GOARCH=arm64 go build -v -o dist/build/windows-arm64/connet.exe github.com/connet-dev/connet/cmd/connet

CONNET_VERSION ?= $(shell git describe --exact-match --tags 2> /dev/null || git rev-parse --short HEAD)

release-archive:
	mkdir dist/archive
	for x in $(shell ls dist/build); do \
	  if [[ $$x == windows* ]]; then \
	    zip --junk-paths dist/archive/connet-$(CONNET_VERSION)-$$x.zip dist/build/$$x/*; \
	  else \
	    tar -czf dist/archive/connet-$(CONNET_VERSION)-$$x.tar.gz -C dist/build/$$x connet; \
	  fi \
	done

release: release-clean release-build release-archive
