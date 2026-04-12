package webflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSystemBrowserOpen tests the Open method for various platforms and scenarios.
func TestSystemBrowserOpen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		url             string
		mockOpenBrowser func(url string, runCmd func(string, ...string) error) error
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "Linux success",
			url:  "https://example.com",
			mockOpenBrowser: func(url string, runCmd func(string, ...string) error) error {
				return runCmd("xdg-open", url)
			},
			wantErr: false,
		},
		{
			name: "macOS success",
			url:  "https://example.com",
			mockOpenBrowser: func(url string, runCmd func(string, ...string) error) error {
				return runCmd("open", url)
			},
			wantErr: false,
		},
		{
			name: "Unsupported platform",
			url:  "https://example.com",
			mockOpenBrowser: func(_ string, _ func(string, ...string) error) error {
				return errors.New("openBrowser: unsupported operating system: plan9")
			},
			wantErr:    true,
			wantErrMsg: "unsupported operating system: plan9",
		},
		{
			name: "Command not found",
			url:  "https://example.com",
			mockOpenBrowser: func(url string, runCmd func(string, ...string) error) error {
				return runCmd("xdg-open", url)
			},
			wantErr:    true,
			wantErrMsg: "command xdg-open not found",
		},
		{
			name: "Invalid URL",
			url:  "://invalid",
			mockOpenBrowser: func(url string, runCmd func(string, ...string) error) error {
				return runCmd("xdg-open", url)
			},
			wantErr:    true,
			wantErrMsg: "failed to open browser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Set up RunCmd based on test case
			var mockRunCmd func(prog string, args ...string) error
			switch tt.name {
			case "Linux success":
				mockRunCmd = func(prog string, args ...string) error {
					if prog != "xdg-open" || args[0] != tt.url {
						return fmt.Errorf("expected xdg-open %s, got %s %v", tt.url, prog, args)
					}
					return nil
				}
			case "macOS success":
				mockRunCmd = func(prog string, args ...string) error {
					if prog != "open" || args[0] != tt.url {
						return fmt.Errorf("expected open %s, got %s %v", tt.url, prog, args)
					}
					return nil
				}
			case "Command not found":
				mockRunCmd = func(prog string, _ ...string) error {
					return fmt.Errorf("command %s not found: exec: %q: executable file not found in $PATH", prog, prog)
				}
			case "Invalid URL":
				mockRunCmd = func(_ string, _ ...string) error {
					return errors.New("failed to open browser")
				}
			default: // Unsupported platform
				mockRunCmd = func(_ string, _ ...string) error {
					return errors.New("unexpected call to RunCmd on unsupported platform")
				}
			}

			b := &SystemBrowser{
				RunCmd:      mockRunCmd,
				OpenBrowser: tt.mockOpenBrowser,
			}
			err := b.Open(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
			}
		})
	}
}

func TestNewBrowser(t *testing.T) {
	t.Parallel()
	b := NewBrowser()
	if b == nil {
		t.Fatal("NewBrowser returned nil")
	}
	if _, ok := b.(*SystemBrowser); !ok {
		t.Errorf("NewBrowser returned %T, want *SystemBrowser", b)
	}
}

func TestNewSystemBrowser(t *testing.T) {
	t.Parallel()
	b := NewSystemBrowser()
	if b == nil {
		t.Fatal("NewSystemBrowser returned nil")
	}
	if b.RunCmd == nil {
		t.Error("NewSystemBrowser did not initialize RunCmd")
	}
	if b.OpenBrowser == nil {
		t.Error("NewSystemBrowser did not initialize OpenBrowser")
	}
}

func TestSystemBrowserDefaultRunCmd(t *testing.T) {
	t.Parallel()
	b := &SystemBrowser{
		OpenBrowser: func(url string, runCmd func(string, ...string) error) error {
			return runCmd("mythical-command", url)
		},
	} // RunCmd is nil
	err := b.Open("https://example.com")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		// Expect an error due to command not being found in test environment
		t.Errorf("expected command not found error, got %v", err)
	}
}
