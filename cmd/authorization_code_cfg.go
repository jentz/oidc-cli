package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/oidc"
)

type CustomArgsFlag []string

func (c *CustomArgsFlag) String() string {
	return ""
}

func (c *CustomArgsFlag) Set(value string) error {
	*c = append(*c, value)
	return nil
}

func parseAuthorizationCodeFlags(name string, args []string, oidcConf *oidc.Config) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", oidcConf.IssuerURL, "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", oidcConf.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.AuthorizationEndpoint, "authorization-url", "", "override authorization url")
	flags.StringVar(&oidcConf.TokenEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.ClientID, "client-id", oidcConf.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", oidcConf.ClientSecret, "set client secret (required if not using PKCE)")
	flags.BoolVar(&oidcConf.SkipTLSVerify, "skip-tls-verify", oidcConf.SkipTLSVerify, "skip TLS certificate verification")
	flags.Var(&oidcConf.AuthMethod, "auth-method", "auth method to use (client_secret_basic or client_secret_post)")
	flags.StringVar(&oidcConf.DPoPPrivateKeyFile, "dpop-private-key", "", "file to read private key from (eg. for DPoP)")
	flags.StringVar(&oidcConf.DPoPPublicKeyFile, "dpop-public-key", "", "file to read public key from (eg. for DPoP)")

	var flowConf oidc.AuthorizationCodeFlowConfig
	flags.StringVar(&flowConf.Scopes, "scopes", "openid", "set scopes as a space separated list")
	flags.StringVar(&flowConf.CallbackURI, "callback-uri", "http://localhost:9555/callback",
		"set callback uri (default: http://localhost:9555/callback), this will also be used as the redirect_uri in the authorization request unless overridden by -redirect-uri")
	flags.StringVar(&flowConf.RedirectURI, "redirect-uri", "", "set the redirect_uri parameter")
	flags.StringVar(&flowConf.Prompt, "prompt", "", "set prompt parameter to login, consent, select_account, or none")
	flags.StringVar(&flowConf.AcrValues, "acr-values", "", "set acr_values parameter")
	flags.StringVar(&flowConf.LoginHint, "login-hint", "", "set login_hint parameter")
	flags.StringVar(&flowConf.MaxAge, "max-age", "", "set max_age parameter")
	flags.StringVar(&flowConf.UILocales, "ui-locales", "", "set ui_locales parameter")
	flags.StringVar(&flowConf.State, "state", "", "set state parameter")
	var customArgs CustomArgsFlag
	flags.Var(&customArgs, "custom", "custom authorization parameters, argument can be given multiple times")
	flags.BoolVar(&flowConf.PKCE, "pkce", false, "use proof-key for code exchange (PKCE)")
	flags.BoolVar(&flowConf.PAR, "par", false, "use pushed authorization requests")
	flags.BoolVar(&flowConf.DPoP, "dpop", false, "use dpop-bound access tokens")

	runner = &oidc.AuthorizationCodeFlow{
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
			oidcConf.ClientSecret == "" && !flowConf.PKCE,
			"client-secret is required unless using PKCE",
		},
		{
			flowConf.Scopes == "",
			"scopes are required",
		},
		{
			flowConf.CallbackURI == "",
			"callback-uri is required",
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
