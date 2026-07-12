package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

const binaryEnv = "OIDC_CLI_BIN"

type statFunc func(string) (os.FileInfo, error)

// Result captures the observable outcome of running oidc-cli as a black-box
// command-line program.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// JSON parses stdout as a JSON object for commands that emit token responses.
func (r Result) JSON(tb testing.TB) map[string]any {
	tb.Helper()

	var out map[string]any
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		tb.Fatalf("stdout is not a JSON object: %v\nstdout:\n%s\nstderr:\n%s", err, r.Stdout, r.Stderr)
	}
	return out
}

// RequireBinary returns the compiled oidc-cli binary path from OIDC_CLI_BIN.
// Missing or invalid configuration is a harness failure, not a skipped test.
func RequireBinary(tb testing.TB) string {
	tb.Helper()

	path, err := resolveBinary(os.Getenv, os.Stat)
	if err != nil {
		tb.Fatal(err)
	}
	return path
}

// Run executes the compiled oidc-cli binary with args and captures its exit
// status, stdout, and stderr.
func Run(tb testing.TB, args ...string) Result {
	tb.Helper()
	return RunWithContext(context.Background(), tb, args...)
}

// RunWithContext executes oidc-cli with args and captures its observable
// process result.
func RunWithContext(ctx context.Context, tb testing.TB, args ...string) Result {
	tb.Helper()

	bin := RequireBinary(tb)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- acceptance tests intentionally execute the configured oidc-cli binary.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		tb.Fatalf("oidc-cli command timed out: %v", ctx.Err())
	}

	result := Result{
		ExitCode: 0,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result
		}
		tb.Fatalf("failed to run oidc-cli: %v", err)
	}
	return result
}

func resolveBinary(getenv func(string) string, stat statFunc) (string, error) {
	path := getenv(binaryEnv)
	if path == "" {
		return "", fmt.Errorf("%s must point to the compiled oidc-cli binary", binaryEnv)
	}

	info, err := stat(path)
	if err != nil {
		return "", fmt.Errorf("%s must point to the compiled oidc-cli binary: %w", binaryEnv, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s must point to the compiled oidc-cli binary, got directory %q", binaryEnv, path)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s must point to an executable oidc-cli binary, got %q", binaryEnv, path)
	}

	return path, nil
}
