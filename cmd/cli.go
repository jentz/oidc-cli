package cmd

import (
	"bytes"
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/log"
)

const (
	ExitOK = iota
	ExitError
	ExitHelp
)

// CLI runs the main CLI logic and returns an exit code.
// Optionally accepts a logger to allow test output capture.
func CLI(args []string, logOptions ...log.Option) int {
	logger := log.New(logOptions...)

	globalConf, flagSet, args, _, err := parseGlobalFlags("global flags", args)

	flag.Usage = func() {
		usage(logger, flagSet)
	}

	if errors.Is(err, flag.ErrHelp) {
		flag.Usage()
		return ExitHelp
	} else if err != nil {
		logger.Errorln("error:", err)
		logger.Errorln()
		logger.Errorln("See 'oidc-cli --help' for usage.")
		return ExitError
	}

	// If no command is specified, print usage and exit
	if len(args) < 1 {
		usage(logger)
		return ExitError
	}

	subCmd := args[0]
	subCmdArgs := args[1:]
	return RunCommand(subCmd, subCmdArgs, globalConf, logger)
}

func usage(logger *log.Logger, flags ...*flag.FlagSet) {
	intro := `oidc-cli: is a command-line OIDC and oAuth2 client

Usage:
  oidc-cli [global-flags] <command> [command-flags]`

	logger.Outputln(intro)
	logger.Outputln()
	logger.Outputln("Commands:")
	for _, command := range commands {
		logger.Outputf("  %-18s: %s\n", command.Name, command.Help)
	}

	if len(flags) > 0 {
		logger.Outputln()
		logger.Outputln("Global flags:")
		// Prints a help string for each flag we defined earlier using
		// flag.StringVar (and related functions)
		var buf bytes.Buffer
		flags[0].SetOutput(&buf)
		flags[0].PrintDefaults()
		logger.Outputln(buf.String())
	}

	logger.Outputln()
	logger.Outputf("Run `oidc-cli <command> --help` to get help for a specific command\n\n")
}
