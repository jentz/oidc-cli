package acceptance

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeFileInfo struct {
	name  string
	mode  os.FileMode
	isDir bool
}

func (f fakeFileInfo) Name() string      { return f.name }
func (fakeFileInfo) Size() int64         { return 1 }
func (f fakeFileInfo) Mode() os.FileMode { return f.mode }
func (fakeFileInfo) ModTime() time.Time  { return time.Time{} }
func (f fakeFileInfo) IsDir() bool       { return f.isDir }
func (fakeFileInfo) Sys() any            { return nil }

func TestResolveBinaryRequiresOIDCCLIBin(t *testing.T) {
	t.Parallel()

	_, err := resolveBinary(func(string) string { return "" }, func(string) (os.FileInfo, error) {
		t.Fatal("stat should not be called when OIDC_CLI_BIN is missing")
		return nil, nil
	})

	if err == nil {
		t.Fatal("expected missing OIDC_CLI_BIN to fail")
	}
	if got, want := err.Error(), "OIDC_CLI_BIN must point to the compiled oidc-cli binary"; got != want {
		t.Fatalf("error message = %q, want %q", got, want)
	}
}

func TestResolveBinaryRejectsInvalidPath(t *testing.T) {
	t.Parallel()

	statErr := errors.New("no such file")
	_, err := resolveBinary(func(string) string { return "/missing/oidc-cli" }, func(string) (os.FileInfo, error) {
		return nil, statErr
	})

	if err == nil {
		t.Fatal("expected invalid OIDC_CLI_BIN to fail")
	}
	if got := err.Error(); !strings.Contains(got, "OIDC_CLI_BIN must point to the compiled oidc-cli binary") || !strings.Contains(got, "no such file") {
		t.Fatalf("error message = %q, want binary-path misconfiguration with stat error", got)
	}
}

func TestResolveBinaryRejectsNonExecutableFile(t *testing.T) {
	t.Parallel()

	_, err := resolveBinary(func(string) string { return "/tmp/oidc-cli" }, func(string) (os.FileInfo, error) {
		return fakeFileInfo{name: "oidc-cli", mode: 0o644}, nil
	})

	if err == nil {
		t.Fatal("expected non-executable OIDC_CLI_BIN to fail")
	}
	if got, want := err.Error(), "OIDC_CLI_BIN must point to an executable oidc-cli binary, got \"/tmp/oidc-cli\""; got != want {
		t.Fatalf("error message = %q, want %q", got, want)
	}
}

func TestResolveBinaryAcceptsExecutableFile(t *testing.T) {
	t.Parallel()

	got, err := resolveBinary(func(string) string { return "/tmp/oidc-cli" }, func(string) (os.FileInfo, error) {
		return fakeFileInfo{name: "oidc-cli", mode: 0o755}, nil
	})
	if err != nil {
		t.Fatalf("resolveBinary returned error: %v", err)
	}
	if want := "/tmp/oidc-cli"; got != want {
		t.Fatalf("binary path = %q, want %q", got, want)
	}
}

func TestResultJSONParsesStdoutObject(t *testing.T) {
	t.Parallel()

	result := Result{Stdout: `{"access_token":"abc123","expires_in":3600,"token_type":"Bearer"}`}

	parsed := result.JSON(t)

	if got, want := parsed["access_token"], "abc123"; got != want {
		t.Fatalf("access_token = %v, want %q", got, want)
	}
	if got, want := parsed["expires_in"], float64(3600); got != want {
		t.Fatalf("expires_in = %v, want %v", got, want)
	}
	if got, want := parsed["token_type"], "Bearer"; got != want {
		t.Fatalf("token_type = %v, want %q", got, want)
	}
}
