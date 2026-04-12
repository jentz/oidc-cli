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

	flags.StringVar(&oidcConf.IssuerURL, "issuer", oidcConf.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", oidcConf.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.ClientID, "client-id", oidcConf.ClientID, "set client ID")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", oidcConf.ClientSecret, "set client secret")
	flags.Var(&oidcConf.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPPrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPPublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

	var flowConf oidc.TokenRefreshFlowConfig
	flags.StringVar(&flowConf.RefreshToken, "refresh-token", "", "refresh token to be used for token refresh")
	flags.StringVar(&flowConf.Scopes, "scopes", "", "set scopes as a space separated list")
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
			oidcConf.IssuerURL == "",
			"issuer is required",
		},
		{
			flowConf.RefreshToken == "",
			"refresh token is required",
		},
		{
			flowConf.DPoP && (oidcConf.DPoPPrivateKeyFile == "" || oidcConf.DPoPPublicKeyFile == ""),
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
