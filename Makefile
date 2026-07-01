# Makefile for oidc-cli

BINARY := oidc-cli
PKG := ./...
COVERAGE_OUT := coverage.out
COVERAGE_HTML := coverage.html

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the oidc-cli binary
	go build -v -o $(BINARY) .

.PHONY: test
test: ## Run tests
	go test $(PKG)

.PHONY: test-race
test-race: ## Run tests with the race detector
	go test -race -count=1 $(PKG)

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: coverage
coverage: ## Run tests with coverage; print total % and write an HTML report
	go test -race -covermode=atomic -coverprofile=$(COVERAGE_OUT) $(PKG)
	@go tool cover -func=$(COVERAGE_OUT) | tail -n 1
	@go tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)

.PHONY: ci
ci: tidy lint coverage ## Run the full local gate (tidy + lint + coverage)
	@echo "ci: ok"

.PHONY: clean
clean: ## Remove build and coverage artifacts and the test cache
	rm -f $(BINARY) $(COVERAGE_OUT) $(COVERAGE_HTML)
	go clean -testcache

.PHONY: lint-clean
lint-clean: ## Purge the golangci-lint cache
	golangci-lint cache clean

.PHONY: realclean
realclean: clean lint-clean ## Run clean, purge the lint cache, and purge the Go build cache
	go clean -cache

# fmt / fmt-check (golangci-lint fmt / --diff) are intentionally omitted for
# now: they require a formatters (gofumpt/goimports) block in .golangci.yaml,
# which is tracked as separate work. Add them once that configuration lands.
