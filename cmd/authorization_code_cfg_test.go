package cmd

import (
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/oidc"
)

func TestParseAuthorizationCodeFlagsResult(t *testing.T) {
	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.AuthorizationCodeFlowConfig
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
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
				"--prompt", "login",
				"--acr-values", "acr_values",
				"--login-hint", "login_hint",
				"--max-age", "max_age",
				"--ui-locales", "ui_locales",
				"--state", "state",
				"--custom", "custom1=value1",
				"--custom", "custom2=value2",
				"--pkce",
				"--par",
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
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:8080/callback",
				Prompt:      "login",
				AcrValues:   "acr_values",
				LoginHint:   "login_hint",
				MaxAge:      "max_age",
				UILocales:   "ui_locales",
				State:       "state",
				CustomArgs: &httpclient.CustomArgs{
					"custom1": "value1",
					"custom2": "value2",
				},
				PKCE: true,
				PAR:  true,
				DPoP: true,
			},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:8080/callback",
				PKCE:        false,
				PAR:         false,
				DPoP:        false,
			},
		},
		{
			"no scopes provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid",
				CallbackURI: "http://localhost:8080/callback",
				PKCE:        false,
				PAR:         false,
				DPoP:        false,
			},
		},
		{
			"no callback-uri provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:9555/callback",
				PKCE:        false,
				PAR:         false,
				DPoP:        false,
			},
		},
		{
			"client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--pkce",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:9555/callback",
				PKCE:        true,
				PAR:         false,
				DPoP:        false,
			},
		},
		{
			"no client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--pkce",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:9555/callback",
				PKCE:        true,
				PAR:         false,
				DPoP:        false,
			},
		},
		{
			"dpop with private and public certificate",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
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
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid profile email",
				CallbackURI: "http://localhost:9555/callback",
				PKCE:        false,
				PAR:         false,
				DPoP:        true,
			},
		},
		{
			"flags after non-flag argument",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerURL:             "https://example.com",
				DiscoveryEndpoint:     "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.AuthorizationCodeFlowConfig{
				Scopes:      "openid",                         // expecting default value as argument is not parsed
				CallbackURI: "http://localhost:9555/callback", // expecting default value as argument is not parsed
				PKCE:        false,
				PAR:         false,
				DPoP:        false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseAuthorizationCodeFlags("authorization_code", tt.args, &oidc.Config{})
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.AuthorizationCodeFlow)
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

func TestParseAuthorizationCodeFlagsError(t *testing.T) {
	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing issuer",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
		},
		{
			"missing client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
		},
		{
			"missing private-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
				"--dpop",
				"--dpop-public-key", "path/to/public-key.pem",
			},
		},
		{
			"missing public-key and dpop",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
				"--dpop",
				"--dpop-private-key", "path/to/private-key.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseAuthorizationCodeFlags("authorization_code", tt.args, &oidc.Config{})
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}
