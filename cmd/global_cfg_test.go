package cmd

import (
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseGlobalFlagsResult(t *testing.T) {
	var tests = []struct {
		name          string
		args          []string
		oidcConf      oidc.Config
		remainingArgs []string
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--skip-tls-verify",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				SkipTLSVerify:     true,
			},
			[]string{},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
			},
			[]string{},
		},
		{
			"verbose flag",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--verbose",
			},
			oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
			},
			[]string{},
		},
		{
			"flags after non-flag argument",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--skip-tls-verify",
			},
			oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				SkipTLSVerify:     false, // expecting default value as argument is not parsed
			},
			[]string{"non-flag-argument", "--skip-tls-verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcConf, flagSet, err := parseGlobalFlags("global", tt.args)
			remainingArgs := flagSet.Args()
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}

			gotConf := *oidcConf
			gotConf.Client = nil // Ignore client in comparison

			if !reflect.DeepEqual(gotConf, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", gotConf, tt.oidcConf)
			}
			if !reflect.DeepEqual(remainingArgs, tt.remainingArgs) {
				t.Errorf("remainingArgs got %v, want %v", remainingArgs, tt.remainingArgs)
			}
		})
	}
}
