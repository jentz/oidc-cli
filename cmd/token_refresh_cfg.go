package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/oidc"
)

func parseTokenRefreshFlags(in ParseInput) (runner CommandRunner, output string, err error) {
	oidcConf := in.Conf
	flags := flag.NewFlagSet(in.Name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", oidcConf.OIDC.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", oidcConf.OIDC.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.OIDC.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", oidcConf.OIDC.ClientID, "set client ID")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", oidcConf.OIDC.ClientSecret, "set client secret")
	flags.Var(&oidcConf.OIDC.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPKeys.PrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPKeys.PublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

	var flowConf oidc.TokenRefreshFlowConfig
	flags.StringVar(&flowConf.RefreshToken, "refresh-token", "", "refresh token to be used for token refresh")
	flags.StringVar(&flowConf.Scope, "scope", "", "set scope as a space separated list")
	flags.BoolVar(&flowConf.DPoP, "dpop", false, "use dpop-bound refresh tokens")

	runner = &oidc.TokenRefreshFlow{
		Config:     oidcConf,
		FlowConfig: &flowConf,
	}

	err = flags.Parse(in.Args)
	if err != nil {
		return nil, buf.String(), err
	}

	if flowConf.RefreshToken == "-" {
		token, err := readTokenFromStdin(in.Stdin, "refresh token")
		if err != nil {
			return nil, buf.String(), err
		}
		flowConf.RefreshToken = token
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
			flowConf.RefreshToken == "",
			"refresh token is required",
		},
		{
			flowConf.DPoP && (oidcConf.DPoPKeys.PrivateKeyFile == "" || oidcConf.DPoPKeys.PublicKeyFile == ""),
			"both dpop-private-key and dpop-public-key are required when using DPoP",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, errors.New("invalid arguments: " + check.message)
		}
	}

	return runner, buf.String(), nil
}
