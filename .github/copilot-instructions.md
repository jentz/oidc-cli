# .github/copilot-instructions.md

# GitHub Copilot Initialization for oidc-cli

This file provides guidance to GitHub Copilot when working with code in this repository.

## Project Overview
- **Language:** Go
- **Type:** CLI application implementing an OIDC (OpenID Connect) client
- **Key Features:**
  - Supports Authorization Code, Client Credentials, Token Refresh, and Token Introspection flows
  - Modular architecture with clear package separation
  - Command pattern for CLI commands

## Directory Structure
- `main.go`: Entry point
- `cmd/`: CLI command parsing, flag handling, and command execution
- `oidc/`: OIDC client logic and flow implementations
- `httpclient/`: HTTP client wrapper for OAuth2/OIDC
- `crypto/`: Cryptographic utilities (PKCE, DPoP, PEM)
- `webflow/`: Browser-based authorization flow and callback server
- `log/`: Logging utilities

## Development Best Practices
- Use idiomatic Go and follow effective Go guidelines
- Write small, testable functions
- Use context for cancellation and timeouts in networked code
- Handle errors explicitly and propagate them up
- Keep CLI flags and configuration logic in `cmd/`

## Testing
- Use Go's standard testing framework
- Run all tests with `go test ./...`
- Use table-driven tests for coverage and clarity
- Mock external dependencies where possible

## Build & Lint
- Build: `make build` or `go build -v -o oidc-cli`
- Lint: `make lint` (uses golangci-lint)
- Clean: `make clean`

## Copilot Usage Tips
- Suggest Go code that follows the above structure and practices
- When generating new commands, implement the `CommandRunner` interface
- For new OIDC flows, add logic in `oidc/` and wire up in `cmd/`
- For cryptographic features, use the `crypto/` package
- For browser-based flows, use the `webflow/` package
- Add and update tests for all new features

---
This file is intended to help Copilot generate code that is idiomatic, maintainable, and consistent with the architecture and practices of this repository.
