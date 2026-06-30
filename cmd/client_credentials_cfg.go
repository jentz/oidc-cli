package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/oidc"
)

func parseClientCredentialsFlags(in ParseInput) (runner CommandRunner, output string, err error) {
	oidcConf := in.Conf
	flags := flag.NewFlagSet(in.Name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", oidcConf.OIDC.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", oidcConf.OIDC.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.OIDC.TokenEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", oidcConf.OIDC.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", oidcConf.OIDC.ClientSecret, "set client secret (required)")
	flags.Var(&oidcConf.OIDC.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")

	var flowConf oidc.ClientCredentialsFlowConfig
	flags.StringVar(&flowConf.Scope, "scope", "", "set scope as a space separated list")

	runner = &oidc.ClientCredentialsFlow{
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
			oidcConf.OIDC.ClientSecret == "",
			"client-secret is required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, errors.New("invalid arguments: " + check.message)
		}
	}

	return runner, buf.String(), nil
}
