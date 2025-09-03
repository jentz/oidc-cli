package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
)

type CommandRunner interface {
	Run(ctx context.Context) error
}

type Command struct {
	Name      string
	Help      string
	Configure func(name string, args []string, cfg *oidc.Config) (config CommandRunner, output string, err error)
}

var commands = []Command{
	{Name: "authorization_code", Help: "Use the Authorization Code flow to obtain tokens.", Configure: parseAuthorizationCodeFlags},
	{Name: "client_credentials", Help: "Use the Client Credentials flow to obtain tokens.", Configure: parseClientCredentialsFlags},
	{Name: "introspect", Help: "Validate a token and retrieve associated claims.", Configure: parseIntrospectFlags},
	{Name: "token_refresh", Help: "Use a refresh token to obtain new tokens.", Configure: parseTokenRefreshFlags},
	{Name: "token_exchange", Help: "Exchange a token for different tokens.", Configure: parseTokenExchangeFlags},
	{Name: "version", Help: "Display the current version of oidc-cli."},
	{Name: "help", Help: "Show help for oidc-cli or a specific command."},
}

func RunCommand(name string, args []string, globalConf *oidc.Config, logger *log.Logger) int {
	cmdIdx := slices.IndexFunc(commands, func(cmd Command) bool {
		return cmd.Name == name
	})

	if cmdIdx < 0 {
		logger.Errorf("error: command \"%s\" not found\n\n", name)
		logger.Errorln("See 'oidc-cli --help' for usage.")
		return ExitError
	}

	cmd := commands[cmdIdx]
	if cmd.Name == "help" {
		flag.Usage()
		return ExitOK
	}

	if cmd.Name == "version" {
		logger.Outputln("oidc-cli version:", oidc.Version)
		return ExitOK
	}

	command, output, err := cmd.Configure(name, args, globalConf)
	if errors.Is(err, flag.ErrHelp) {
		logger.Outputln(output)
		return ExitHelp
	} else if err != nil {
		logger.Errorln("error:", err)
		logger.Errorln()
		logger.Errorf("See 'oidc-cli %s --help' for usage.\n", cmd.Name)
		return ExitError
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	defer func() {
		signal.Stop(signalChan)
		close(signalChan)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle signals
	go func() {
		sig := <-signalChan
		logger.Errorf("\nreceived signal: %s, cancelling...\n", sig)
		cancel()
	}()

	if err := prepareOIDCConfig(ctx, globalConf); err != nil {
		logger.Errorln("configuration error:", err)
		return ExitError
	}

	if err := command.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Errorln("operation cancelled")
			return ExitOK
		} else if errors.Is(err, context.DeadlineExceeded) {
			logger.Errorln("operation timed out")
			return ExitError
		}
		logger.Errorf("error: %v\n", err.Error())
		return ExitError
	}

	return ExitOK
}

func prepareOIDCConfig(ctx context.Context, conf *oidc.Config) error {
	if err := conf.DiscoverEndpoints(ctx); err != nil {
		return fmt.Errorf("failed to discover endpoints: %w", err)
	}
	if err := conf.ReadKeyFiles(); err != nil {
		return fmt.Errorf("failed to read key files: %w", err)
	}
	return nil
}
