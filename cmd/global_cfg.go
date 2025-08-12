package cmd

import (
	"bytes"
	"flag"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
)

func configureGlobalFlags(name string, oidcConf *oidc.Config) (flags *flag.FlagSet) {
	flags = flag.NewFlagSet(name, flag.ContinueOnError)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", "", "set issuer url")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret")

	flags.BoolVar(&oidcConf.SkipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")
	flags.BoolVar(&oidcConf.Verbose, "verbose", false, "enable verbose output")

	return flags
}

func parseGlobalFlags(flags *flag.FlagSet, oidcConf *oidc.Config, args []string) (remainingArgs []string, output string, err error) {
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	err = flags.Parse(args)
	if err != nil {
		return flags.Args(), buf.String(), err
	}

	log.SetDefaultLogger(log.WithVerbose(oidcConf.Verbose))

	oidcConf.Client = httpclient.NewClient(&httpclient.Config{
		SkipTLSVerify: oidcConf.SkipTLSVerify,
	})

	return flags.Args(), buf.String(), nil
}
