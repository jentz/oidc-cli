//go:build acceptance

package acceptance

import (
	"strings"
	"testing"
)

func TestRunsBinaryAndCapturesSuccessfulOutput(t *testing.T) {
	result := Run(t, "version")

	if got, want := result.ExitCode, 0; got != want {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, result.Stdout, result.Stderr)
	}
	if !strings.HasPrefix(result.Stdout, "oidc-cli version: ") {
		t.Fatalf("stdout = %q, want oidc-cli version line", result.Stdout)
	}
	if result.Stderr != "" {
		t.Fatalf("stderr = %q, want empty stderr", result.Stderr)
	}
}

func TestRunsBinaryAndCapturesFailedOutput(t *testing.T) {
	result := Run(t, "not-a-command")

	if got, want := result.ExitCode, 1; got != want {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, result.Stdout, result.Stderr)
	}
	if got, want := result.Stdout, ""; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	for _, want := range []string{`error: command "not-a-command" not found`, "See 'oidc-cli --help' for usage."} {
		if !strings.Contains(result.Stderr, want) {
			t.Fatalf("stderr = %q, want it to contain %q", result.Stderr, want)
		}
	}
	if strings.Contains(result.Stderr, "client_credentials") {
		t.Fatalf("stderr = %q, should not contain unrelated command help", result.Stderr)
	}
}
