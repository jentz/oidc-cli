# Makefile for oidc-cli

.PHONY: help test build lint clean coverage

BINARY=oidc-cli

help:
	@echo "\nUsage: make <target>\n"
	@echo "Targets:"
	@echo "  help     Show this help message"
	@echo "  test     Run all Go tests (go test -race -count=1 ./...)"
	@echo "  build    Build the oidc-cli binary (go build -v -o $(BINARY))"
	@echo "  lint     Run golangci-lint (uses .golangci.yaml config)"
	@echo "  clean    Remove built binaries and test cache"
	@echo "  coverage  Run tests with coverage and generate coverage.out"

# Run all tests

test:
	go test -race -count=1 ./...

# Build the binary

build:
	go build -v -o $(BINARY)

# Lint the codebase

lint:
	golangci-lint run

# Clean up build artifacts and test cache

clean:
	rm -f $(BINARY)
	go clean -testcache

# Run tests with coverage

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
