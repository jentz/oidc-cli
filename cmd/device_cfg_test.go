package cmd

import (
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseDeviceFlags(t *testing.T) {
	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.DeviceFlowConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--authorization-url", "https://example.com/authorize",
				"--token-url", "https://example.com/token",
				"--skip-tls-verify",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scope", "openid profile email",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
				"--dpop-public-key", "path/to/public-key.pem",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "https://example.com/authorize",
				TokenEndpoint:         "https://example.com/token",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				SkipTLSVerify:         true,
				DPoPPrivateKeyFile:    "path/to/private-key.pem",
				DPoPPublicKeyFile:     "path/to/public-key.pem",
			},
			oidc.DeviceFlowConfig{
				Scope: "openid profile email",
				DPoP:  true,
			},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scope", "openid profile email",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.DeviceFlowConfig{
				Scope: "openid profile email",
				DPoP:  false,
			},
		},
		{
			"no scope provided",
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
			oidc.DeviceFlowConfig{
				Scope: "openid",
				DPoP:  false,
			},
		},
		{
			"dpop with private and public certificate",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scope", "openid profile email",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
				"--dpop-public-key", "path/to/public-key.pem",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				DPoPPrivateKeyFile:    "path/to/private-key.pem",
				DPoPPublicKeyFile:     "path/to/public-key.pem",
			},
			oidc.DeviceFlowConfig{
				Scope: "openid profile email",
				DPoP:  true,
			},
		},
		{
			"flags after non-flag argument",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--scope", "openid profile email",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.DeviceFlowConfig{
				Scope: "openid", // expecting default value as argument is not parsed
				DPoP:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseDeviceFlags("device", tt.args, &oidc.Config{})
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.DeviceFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
			}
			if !reflect.DeepEqual(*f.Config, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", *f.Config, tt.oidcConf)
			}
			if !reflect.DeepEqual(*f.FlowConfig, tt.flowConf) {
				t.Errorf("OIDCConfig got %+v, want %+v", *f.FlowConfig, tt.flowConf)
			}
		})
	}
}

func TestParseDeviceFlagsError(t *testing.T) {
	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing issuer",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scope", "openid profile email",
			},
		},
		{
			"missing private-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scope", "openid profile email",
				"--dpop",
				"--dpop-public-key", "path/to/public-key.pem",
			},
		},
		{
			"missing public-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scope", "openid profile email",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseDeviceFlags("device", tt.args, &oidc.Config{})
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}
