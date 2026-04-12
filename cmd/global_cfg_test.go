package cmd

import (
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/oidc"
)

func TestParseGlobalFlagsResult(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name          string
		args          []string
		oidcConf      oidc.Config
		wantVerbose   bool
		remainingArgs []string
	}{
		{
			name: "all flags",
			args: []string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--skip-tls-verify",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidcConf: oidc.Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				SkipTLSVerify:     true,
			},
			remainingArgs: []string{},
		},
		{
			name: "only issuer",
			args: []string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidcConf: oidc.Config{
				IssuerURL:    "https://example.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			remainingArgs: []string{},
		},
		{
			name: "verbose flag",
			args: []string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--verbose",
			},
			oidcConf: oidc.Config{
				IssuerURL:    "https://example.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			wantVerbose:   true,
			remainingArgs: []string{},
		},
		{
			name: "flags after non-flag argument",
			args: []string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--skip-tls-verify",
			},
			oidcConf: oidc.Config{
				IssuerURL:    "https://example.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			remainingArgs: []string{"non-flag-argument", "--skip-tls-verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			oidcConf, flagSet, verbose, err := parseGlobalFlags("global", tt.args)
			remainingArgs := flagSet.Args()
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}

			gotConf := *oidcConf
			gotConf.Logger = nil // Logger is set by NewConfig(), not by flag parsing
			if !reflect.DeepEqual(gotConf, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", gotConf, tt.oidcConf)
			}
			if verbose != tt.wantVerbose {
				t.Errorf("verbose got %v, want %v", verbose, tt.wantVerbose)
			}
			if !reflect.DeepEqual(remainingArgs, tt.remainingArgs) {
				t.Errorf("remainingArgs got %v, want %v", remainingArgs, tt.remainingArgs)
			}
		})
	}
}
