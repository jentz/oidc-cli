//go:build acceptance

package acceptance

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

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
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			tb.Fatalf("oidc-cli command timed out: %v", ctxErr)
		}
		tb.Fatalf("oidc-cli command cancelled: %v", ctxErr)
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
