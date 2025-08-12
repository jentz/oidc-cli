package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"os"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/oidc"
)

func parseIntrospectFlags(name string, args []string, oidcConf *oidc.Config) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", oidcConf.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", oidcConf.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.ClientID, "client-id", oidcConf.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", oidcConf.ClientSecret, "set client secret (required unless bearer token is provided)")
	flags.Var(&oidcConf.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")

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

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	// populate custom args
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

	// Read token from stdin if token equals '-'
	if flowConf.Token == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, buf.String(), err
			}
		}
		flowConf.Token = scanner.Text()
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
			oidcConf.ClientID == "",
			"client-id is required",
		},
		{
			oidcConf.ClientSecret == "" && flowConf.BearerToken == "",
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
