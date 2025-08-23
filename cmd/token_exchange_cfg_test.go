package cmd

import (
	"flag"
	"os"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseTokenExchangeFlagsResult(t *testing.T) {
	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.TokenExchangeFlowConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--introspection-url", "https://example.com/introspection",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--subject-token", "subject-token",
				"--subject-token-type", "subject-token-type",
				"--actor-token", "actor-token",
				"--actor-token-type", "actor-token-type",
				"--audience", "audience",
				"--scope", "scope",
				"--requested-token-type", "requested-token-type",
				"--resource", "resource",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
				"--dpop-public-key", "path/to/public-key.pem",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "https://example.com/.well-known/openid-configuration",
				IntrospectionEndpoint: "https://example.com/introspection",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				DPoPPrivateKeyFile:    "path/to/private-key.pem",
				DPoPPublicKeyFile:     "path/to/public-key.pem",
			},
			oidc.TokenExchangeFlowConfig{
				Resource:           "resource",
				Audience:           "audience",
				Scope:              "scope",
				RequestedTokenType: "requested-token-type",
				SubjectToken:       "subject-token",
				SubjectTokenType:   "subject-token-type",
				ActorToken:         "actor-token",
				ActorTokenType:     "actor-token-type",
				DPoP:               true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseTokenExchangeFlags("token_exchange", tt.args, &oidc.Config{})
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.TokenExchangeFlow)
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

func TestParseTokenExchangeFlagsError(t *testing.T) {
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
			"missing client-id",
			[]string{
				"--issuer", "https://example.com",
				"--client-secret", "client-secret",
			},
			"invalid arguments: client-id is required",
		},
		{
			"missing client-secret",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
			},
			"invalid arguments: client-secret is required",
		},
		{
			"missing subject token",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			"invalid arguments: subject token is required",
		},
		{
			"undefined argument provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--undefined-argument", "undefined-argument",
				"--subject-token", "subject-token",
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
		{
			"missing private-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--subject-token", "subject-token",
				"--dpop",
				"--dpop-public-key", "path/to/public-key.pem",
			},
			"invalid arguments: both dpop-private-key and dpop-public-key are required when using DPoP",
		},
		{
			"missing public-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--subject-token", "subject-token",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
			},
			"invalid arguments: both dpop-private-key and dpop-public-key are required when using DPoP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseTokenExchangeFlags("token_exchange", tt.args, &oidc.Config{})
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

func TestParseTokenExchangeFlagsStdin(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "successful stdin read",
			input:         "test-subject-token\n",
			expectError:   false,
			expectedToken: "test-subject-token",
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
				"--subject-token", "-", // This triggers stdin reading
				"--subject-token-type", "subject-token-type",
			}

			runner, output, err := parseTokenExchangeFlags("token_exchange", args, &oidc.Config{})

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

			f, ok := runner.(*oidc.TokenExchangeFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
				return
			}

			if f.FlowConfig.SubjectToken != tt.expectedToken {
				t.Errorf("SubjectToken got %q, want %q", f.FlowConfig.SubjectToken, tt.expectedToken)
			}
		})
	}
}

func TestParseTokenExchangeFlagsStdinError(t *testing.T) {
	// Save original stdin
	originalStdin := os.Stdin
	defer func() { os.Stdin = originalStdin }()

	expectedError := "no subject token provided on stdin"

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
		"--subject-token", "-", // This triggers stdin reading
		"--subject-token-type", "subject-token-type",
	}

	_, _, err = parseTokenExchangeFlags("token_exchange", args, &oidc.Config{})
	if err == nil {
		t.Error("expected error from empty stdin, got nil")
	}
	if err.Error() != expectedError {
		t.Errorf("expected error message %v, got %v", expectedError, err)
	}
}
