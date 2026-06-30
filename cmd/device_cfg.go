package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/oidc"
)

func parseDeviceFlags(in ParseInput) (runner CommandRunner, output string, err error) {
	oidcConf := in.Conf
	flags := flag.NewFlagSet(in.Name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", oidcConf.OIDC.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", oidcConf.OIDC.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.OIDC.AuthorizationEndpoint, "authorization-url", "", "override authorization url")
	flags.StringVar(&oidcConf.OIDC.TokenEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.OIDC.DeviceAuthorizationEndpoint, "device-authorization-url", "", "override device authorization url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", oidcConf.OIDC.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", oidcConf.OIDC.ClientSecret, "set client secret (required if not using PKCE)")
	// Effective only as a global flag (the client is built before subcommands parse); accepted here but ignored.
	var skipTLSVerify bool
	flags.BoolVar(&skipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")
	flags.Var(&oidcConf.OIDC.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPKeys.PrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPKeys.PublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

	var flowConf oidc.DeviceFlowConfig
	flags.BoolVar(&flowConf.PKCE, "pkce", false, "use proof-key for code exchange (PKCE)")
	flags.StringVar(&flowConf.Scope, "scope", "openid", "set scope as a space separated list")
	flags.BoolVar(&flowConf.DPoP, "dpop", false, "use dpop-bound access tokens")

	runner = &oidc.DeviceFlow{
		Config:     oidcConf,
		FlowConfig: &flowConf,
	}

	err = flags.Parse(in.Args)
	if err != nil {
		return nil, buf.String(), err
	}

	var invalidArgsChecks = []struct {
		condition bool
		message   string
	}{
		{
			oidcConf.OIDC.IssuerURL == "",
			"issuer is required",
		},
		{
			oidcConf.OIDC.ClientID == "",
			"client-id is required",
		},
		{
			flowConf.Scope == "",
			"scope is required",
		},
		{
			flowConf.DPoP && (oidcConf.DPoPKeys.PrivateKeyFile == "" || oidcConf.DPoPKeys.PublicKeyFile == ""),
			"both dpop-private-key and dpop-public-key are required when using DPoP",
		},
		{
			oidcConf.OIDC.ClientSecret == "" && !flowConf.PKCE,
			"client-secret is required unless using PKCE",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, errors.New("invalid arguments: " + check.message)
		}
	}

	return runner, buf.String(), nil
}
