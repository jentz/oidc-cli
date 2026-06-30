package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/oidc"
)

func parseIntrospectFlags(in ParseInput) (runner CommandRunner, output string, err error) {
	oidcConf := in.Conf
	flags := flag.NewFlagSet(in.Name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", oidcConf.OIDC.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", oidcConf.OIDC.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.OIDC.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", oidcConf.OIDC.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", oidcConf.OIDC.ClientSecret, "set client secret (required unless bearer token is provided)")
	flags.Var(&oidcConf.OIDC.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")

	var flowConf oidc.IntrospectFlowConfig
	flags.StringVar(&flowConf.BearerToken, "bearer-token", "", "bearer token for authorization (required unless client secret is provided)")
	flags.StringVar(&flowConf.Token, "token", "", "token to be introspected or '-' to read token from stdin (required)")
	flags.StringVar(&flowConf.TokenTypeHint, "token-type", "access_token", "token type hint (e.g. access_token")
	flags.StringVar(&flowConf.AcceptMediaType, "accept-header", "", "set a custom accept header to request a format (e.g. application/json)")
	var customArgs CustomArgsFlag
	flags.Var(&customArgs, "custom", "custom parameters to send in the body of the request, argument can be given multiple times")

	runner = &oidc.IntrospectFlow{
		Config:     oidcConf,
		FlowConfig: &flowConf,
	}

	err = flags.Parse(in.Args)
	if err != nil {
		return nil, buf.String(), err
	}

	if len(customArgs) > 0 {
		if flowConf.CustomArgs == nil {
			flowConf.CustomArgs = &httpclient.CustomArgs{}
		}
		for _, arg := range customArgs {
			err := flowConf.CustomArgs.Set(arg)
			if err != nil {
				return nil, buf.String(), err
			}
		}
	}

	if flowConf.Token == "-" {
		token, err := readTokenFromStdin(in.Stdin, "token")
		if err != nil {
			return nil, buf.String(), err
		}
		flowConf.Token = token
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
			oidcConf.OIDC.ClientSecret == "" && flowConf.BearerToken == "",
			"client-secret or bearer-token is required",
		},
		{
			flowConf.Token == "",
			"token is required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, errors.New("invalid arguments: " + check.message)
		}
	}

	return runner, buf.String(), nil
}
