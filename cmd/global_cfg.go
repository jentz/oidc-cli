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

	flags = flag.NewFlagSet("global flags", flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", "", "set issuer url")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret")

	flags.BoolVar(&oidcConf.SkipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")
	flags.BoolVar(&verbose, "verbose", false, "enable verbose output")

	err = flags.Parse(args)
	if err != nil {
		return nil, flags, err
	}

	logger.SetVerbose(verbose)
	oidcConf.Logger = logger
	oidcConf.Client = httpclient.NewClient(&httpclient.Config{
		SkipTLSVerify: oidcConf.SkipTLSVerify,
		Logger:        logger,
	})

	return oidcConf, flags, nil
}
