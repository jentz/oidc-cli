package cmd

import (
	"bytes"
	"flag"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
)

func parseGlobalFlags(name string, args []string) (oidcConf *oidc.Config, flags *flag.FlagSet, err error) {
	oidcConf = &oidc.Config{}

	flags = flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", "", "set issuer url")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret")

	var skipTLSVerify bool
	flags.BoolVar(&skipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")

	var verbose bool
	flags.BoolVar(&verbose, "verbose", false, "enable verbose output")

	err = flags.Parse(args)
	if err != nil {
		return nil, flags, err
	}

	log.SetDefaultLogger(log.WithVerbose(verbose))

	oidcConf.SkipTLSVerify = skipTLSVerify // temporary compatibility
	oidcConf.Client = httpclient.NewClient(&httpclient.Config{
		SkipTLSVerify: skipTLSVerify,
	})

	return oidcConf, flags, nil
}
