package cmd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseClientCredentialsFlagsResult(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.ClientCredentialsFlowConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--token-url", "https://example.com/token",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				TokenEndpoint:     "https://example.com/token",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
			},
			oidc.ClientCredentialsFlowConfig{
				Scopes: "",
			},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.ClientCredentialsFlowConfig{
				Scopes: "",
			},
		},
		{
			"scopes provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "expected",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.ClientCredentialsFlowConfig{
				Scopes: "expected",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runner, output, err := parseClientCredentialsFlags("client_credentials", tt.args, &oidc.Config{}, strings.NewReader(""))
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.ClientCredentialsFlow)
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

func TestParseClientCredentialsFlagsError(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing discovery-url and token-url",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
		},
		{
			"missing client-secret",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, output, err := parseClientCredentialsFlags("client_credentials", tt.args, &oidc.Config{}, strings.NewReader(""))
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}
