package cmd

import (
	"flag"
	"os"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseTokenRefreshFlagsResult(t *testing.T) {
	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.TokenRefreshFlowConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--introspection-url", "https://example.com/introspection",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--refresh-token", "refresh-token",
				"--scopes", "openid profile email",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "https://example.com/.well-known/openid-configuration",
				IntrospectionEndpoint: "https://example.com/introspection",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.TokenRefreshFlowConfig{
				Scopes:       "openid profile email",
				RefreshToken: "refresh-token",
			},
		},
		{
			"only issuer, no scopes",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--refresh-token", "refresh-token",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				IntrospectionEndpoint: "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.TokenRefreshFlowConfig{
				RefreshToken: "refresh-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseTokenRefreshFlags("token_refresh", tt.args, &oidc.Config{})
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.TokenRefreshFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
			}
			if !reflect.DeepEqual(*f.Config, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", *f.Config, tt.oidcConf)
			}
			if !reflect.DeepEqual(*f.FlowConfig, tt.flowConf) {
				t.Errorf("FlowConfig got %+v, want %+v", *f.FlowConfig, tt.flowConf)
			}
		})
	}
}

func TestParseTokenRefreshFlagsError(t *testing.T) {
	var tests = []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			"missing issuer",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			"invalid arguments: issuer is required",
		},
		{
			"missing refresh token",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			"invalid arguments: refresh token is required",
		},
		{
			"undefined argument provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--undefined-argument", "undefined-argument",
				"--refresh-token", "refresh-token",
			},
			"flag provided but not defined: -undefined-argument",
		},
		{
			"help flag",
			[]string{
				"--help",
			},
			flag.ErrHelp.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseTokenRefreshFlags("token_refresh", tt.args, &oidc.Config{})
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
			if err != nil && err.Error() != tt.expectedError {
				t.Errorf("err got %v, want %v", err.Error(), tt.expectedError)
			}
		})
	}
}

func TestParseTokenRefreshFlagsStdin(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "successful stdin read",
			input:         "test-refresh-token\n",
			expectError:   false,
			expectedToken: "test-refresh-token",
		},
		{
			name:        "empty input (EOF)",
			input:       "",
			expectError: true,
		},
		{
			name:          "whitespace only input",
			input:         "   \n",
			expectError:   false,
			expectedToken: "   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original stdin
			originalStdin := os.Stdin
			defer func() { os.Stdin = originalStdin }()

			// Create pipe to simulate stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("Failed to create pipe: %v", err)
			}
			os.Stdin = r

			// Write test input to pipe
			go func() {
				defer func() { _ = w.Close() }()
				if tt.input != "" {
					_, _ = w.WriteString(tt.input)
				}
			}()

			args := []string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--refresh-token", "-", // This triggers stdin reading
			}

			runner, output, err := parseTokenRefreshFlags("token_refresh", args, &oidc.Config{})

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}

			f, ok := runner.(*oidc.TokenRefreshFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
				return
			}

			if f.FlowConfig.RefreshToken != tt.expectedToken {
				t.Errorf("RefreshToken got %q, want %q", f.FlowConfig.RefreshToken, tt.expectedToken)
			}
		})
	}
}

func TestParseTokenRefreshFlagsStdinError(t *testing.T) {
	// Save original stdin
	originalStdin := os.Stdin
	defer func() { os.Stdin = originalStdin }()

	expectedError := "no refresh token provided on stdin"

	// Test the EOF case (no input) - this should return flag.ErrHelp
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	_ = w.Close() // Close write end immediately to simulate EOF
	os.Stdin = r
	defer func() { _ = r.Close() }()

	args := []string{
		"--issuer", "https://example.com",
		"--client-id", "client-id",
		"--client-secret", "client-secret",
		"--refresh-token", "-", // This triggers stdin reading
	}

	_, _, err = parseTokenRefreshFlags("token_refresh", args, &oidc.Config{})
	if err == nil {
		t.Error("expected error from empty stdin, got nil")
	}
	if err.Error() != expectedError {
		t.Errorf("expected error message %v, got %v", expectedError, err)
	}
}
