package cmd

import (
	"bytes"
	"flag"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
)

func initGlobalConfig(args []string, logger *log.Logger) (oidcConf *oidc.Config, flags *flag.FlagSet, err error) {
	oidcConf = oidc.NewConfig()

	var verbose bool
	var skipTLSVerify bool

	flags = flag.NewFlagSet("global flags", flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.OIDC.IssuerURL, "issuer", "", "set issuer url")
	flags.StringVar(&oidcConf.OIDC.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.OIDC.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&oidcConf.OIDC.ClientSecret, "client-secret", "", "set client secret")

	flags.BoolVar(&skipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")
	flags.BoolVar(&verbose, "verbose", false, "enable verbose output")

	err = flags.Parse(args)
	if err != nil {
		return nil, flags, err
	}

	logger.SetVerbose(verbose)
	oidcConf.Runtime.Logger = logger
	oidcConf.Runtime.Client = httpclient.NewClient(&httpclient.Config{
		SkipTLSVerify: skipTLSVerify,
		Logger:        logger,
	})

	return oidcConf, flags, nil
}
