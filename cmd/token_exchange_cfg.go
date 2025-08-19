package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"os"

	"github.com/jentz/oidc-cli/oidc"
)

func parseTokenExchangeFlags(name string, args []string, oidcConf *oidc.Config) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", oidcConf.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", oidcConf.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.ClientID, "client-id", oidcConf.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", oidcConf.ClientSecret, "set client secret (required)")
	flags.Var(&oidcConf.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPPrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPPublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

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

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	// Read subject token from stdin if token equals '-'
	if flowConf.SubjectToken == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, buf.String(), err
			}
			return nil, buf.String(), errors.New("no subject token provided on stdin")
		}
		flowConf.SubjectToken = scanner.Text()
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
			oidcConf.ClientSecret == "",
			"client-secret is required",
		},
		{
			flowConf.SubjectToken == "",
			"subject token is required",
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
