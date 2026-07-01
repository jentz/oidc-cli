package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
)

func TestParseGlobalFlagsResult(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name          string
		args          []string
		oidcConf      oidc.Config
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
				OIDC: oidc.OIDCConfig{
					IssuerURL:         "https://example.com",
					DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
					ClientID:          "client-id",
					ClientSecret:      "client-secret",
				},
			},
			remainingArgs: make([]string, 0),
		},
		{
			name: "only issuer",
			args: []string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidcConf: oidc.Config{
				OIDC: oidc.OIDCConfig{
					IssuerURL:    "https://example.com",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			remainingArgs: make([]string, 0),
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
				OIDC: oidc.OIDCConfig{
					IssuerURL:    "https://example.com",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			remainingArgs: make([]string, 0),
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
				OIDC: oidc.OIDCConfig{
					IssuerURL:    "https://example.com",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			remainingArgs: []string{"non-flag-argument", "--skip-tls-verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger := log.Discard()
			oidcConf, flagSet, err := initGlobalConfig(tt.args, logger)
			remainingArgs := flagSet.Args()
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}

			if oidcConf.Runtime.Logger != logger {
				t.Error("expected Logger to be the injected instance")
			}
			if oidcConf.Runtime.Client == nil {
				t.Error("expected Client to be set")
			}

			gotConf := *oidcConf
			gotConf.Runtime = oidc.Runtime{}
			if !reflect.DeepEqual(gotConf, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", gotConf, tt.oidcConf)
			}
			if !reflect.DeepEqual(remainingArgs, tt.remainingArgs) {
				t.Errorf("remainingArgs got %v, want %v", remainingArgs, tt.remainingArgs)
			}
		})
	}
}

// TestInitGlobalConfigWiresSkipTLSVerify pins that --skip-tls-verify is wired
// from the command boundary through to the constructed client: with the flag,
// the client reaches a self-signed server; without it, the same server is
// rejected. The control case ensures the flag, not an always-on default, is
// what relaxes verification.
func TestInitGlobalConfigWiresSkipTLSVerify(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"flag skips verification", []string{"--skip-tls-verify"}, false},
		{"default rejects self-signed cert", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conf, _, err := initGlobalConfig(tt.args, log.Discard())
			if err != nil {
				t.Fatalf("initGlobalConfig: %v", err)
			}
			_, err = conf.Runtime.Client.Get(context.Background(), ts.URL, nil)
			if tt.wantErr && err == nil {
				t.Error("Client.Get error = nil, want TLS verification error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Client.Get error = %v, want nil", err)
			}
		})
	}
}
