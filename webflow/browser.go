package webflow

import (
	"fmt"
	"os/exec"
)

// Browser defines an interface for opening URLs in a web browser.
// Implementations should provide a method to open a URL.
type Browser interface {
	Open(url string) error
}

// SystemBrowser opens URLs using system-specific commands (e.g., xdg-open on Linux,
// open on macOS, cmd /c start on Windows).
type SystemBrowser struct {
	RunCmd      func(prog string, args ...string) error
	OpenBrowser func(url string, runCmd func(string, ...string) error) error
}

// Ensure SystemBrowser implements the Browser interface.
var _ Browser = (*SystemBrowser)(nil)

// NewBrowser returns a Browser implementation suitable for the current platform.
func NewBrowser() Browser {
	return NewSystemBrowser()
}

// NewSystemBrowser creates a new SystemBrowser instance with a default command runner.
// It uses the runCmd function to execute system commands for opening URLs.
func NewSystemBrowser() *SystemBrowser {
	return &SystemBrowser{
		RunCmd:      runCmd,
		OpenBrowser: openBrowser,
	}
}

// Open opens the specified URL in the system’s default browser.
// It uses platform-specific commands (e.g., xdg-open on Linux, open on macOS).
// Returns an error if the command is not found or fails to execute.
func (s *SystemBrowser) Open(url string) error {
	if s.RunCmd == nil {
		s.RunCmd = runCmd
	}
	if s.OpenBrowser == nil {
		s.OpenBrowser = openBrowser
	}
	return s.OpenBrowser(url, s.RunCmd)
}

// runCmd executes a command with the given program and arguments.
// It checks if the program exists before running to provide better error messages.
func runCmd(prog string, args ...string) error {
	if _, err := exec.LookPath(prog); err != nil {
		return fmt.Errorf("command %s not found: %w", prog, err)
	}
	// #nosec G204 -- prog is a fixed per-platform literal, LookPath-validated,
	// and the URL is a distinct argv element (no shell), so it cannot inject.
	cmd := exec.Command(prog, args...)
	return cmd.Run()
}
