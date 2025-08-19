package cmd

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/log"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func resetLogger() {
	log.SetDefaultLogger(log.WithVerbose(false))
}

func TestCLI_HelpFlag(t *testing.T) {
	resetFlags()
	resetLogger()
	var out bytes.Buffer
	code := CLI([]string{"--help"}, log.WithOutput(&out, &out))
	if code != ExitHelp {
		t.Errorf("expected ExitHelp, got %d", code)
	}
	if !strings.Contains(out.String(), "Commands:") {
		t.Errorf("expected usage output, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "Global flags:") {
		t.Errorf("expected usage output, got: %s", out.String())
	}
}

func TestCLI_NoArgs(t *testing.T) {
	resetFlags()
	resetLogger()
	var out bytes.Buffer
	code := CLI([]string{}, log.WithOutput(&out, &out))
	if code != ExitError {
		t.Errorf("expected ExitError, got %d", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("expected usage output, got: %s", out.String())
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	resetFlags()
	resetLogger()
	var out bytes.Buffer
	code := CLI([]string{"unknowncmd"}, log.WithOutput(&out, &out))
	if code != ExitError {
		t.Errorf("expected ExitError, got %d", code)
	}
	if !strings.Contains(out.String(), "not found") {
		t.Errorf("expected not found error, got: %s", out.String())
	}
}

func TestCLI_VersionCommand(t *testing.T) {
	resetFlags()
	resetLogger()
	var out bytes.Buffer
	code := CLI([]string{"version"}, log.WithOutput(&out, &out))
	if code != ExitOK {
		t.Errorf("expected ExitOK, got %d", code)
	}
	if !strings.Contains(out.String(), "oidc-cli version:") {
		t.Errorf("expected version output, got: %s", out.String())
	}
}
