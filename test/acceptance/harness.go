package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
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
