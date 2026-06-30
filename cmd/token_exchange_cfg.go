package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/oidc"
)

func parseTokenExchangeFlags(in ParseInput) (runner CommandRunner, output string, err error) {
	oidcConf := in.Conf
	flags := flag.NewFlagSet(in.Name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", oidcConf.OIDC.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", oidcConf.OIDC.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.OIDC.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", oidcConf.OIDC.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", oidcConf.OIDC.ClientSecret, "set client secret")
	flags.Var(&oidcConf.OIDC.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPKeys.PrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPKeys.PublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

	var flowConf oidc.TokenExchangeFlowConfig
	flags.StringVar(&flowConf.SubjectToken, "subject-token", "", "subject token to be exchanged (required)")
	flags.StringVar(&flowConf.SubjectTokenType, "subject-token-type", "urn:ietf:params:oauth:token-type:access_token", "subject token type to be used for the exchange")
	flags.StringVar(&flowConf.Audience, "audience", "", "audience to be used for the token exchange")
	flags.StringVar(&flowConf.Scope, "scope", "", "scope to be used for the token exchange")
	flags.StringVar(&flowConf.RequestedTokenType, "requested-token-type", "", "requested token type to be used for the exchange (eg. 'urn:ietf:params:oauth:token-type:access_token')")
	flags.StringVar(&flowConf.Resource, "resource", "", "resource to be used for the token exchange")
	flags.StringVar(&flowConf.ActorToken, "actor-token", "", "actor token to be used for the token exchange")
	flags.StringVar(&flowConf.ActorTokenType, "actor-token-type", "", "actor token type to be used for the exchange (eg. 'urn:ietf:params:oauth:token-type:access_token')")
	flags.BoolVar(&flowConf.DPoP, "dpop", false, "use DPoP-bound access tokens")

	runner = &oidc.TokenExchangeFlow{
		Config:     oidcConf,
		FlowConfig: &flowConf,
	}

	err = flags.Parse(in.Args)
	if err != nil {
		return nil, buf.String(), err
	}

	if flowConf.SubjectToken == "-" {
		token, err := readTokenFromStdin(in.Stdin, "subject token")
		if err != nil {
			return nil, buf.String(), err
		}
		flowConf.SubjectToken = token
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
			flowConf.SubjectToken == "",
			"subject token is required",
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
