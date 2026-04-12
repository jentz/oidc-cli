package log

import (
	"fmt"
	"io"
	"os"
)

// Logger holds the configuration for logging.
type Logger struct {
	verbose bool
	errOut  io.Writer
	stdOut  io.Writer
}

// Discard returns a logger that discards all output. Each call returns a
// new instance so callers cannot mutate shared state.
func Discard() *Logger {
	return New(WithOutput(io.Discard, io.Discard))
}

type Option func(*Logger)

// WithVerbose enables verbose logging.
func WithVerbose(verbose bool) Option {
	return func(l *Logger) {
		l.verbose = verbose
	}
}

// WithStderr sets the writer for error output.
func WithStderr(w io.Writer) Option {
	return func(l *Logger) {
		l.errOut = w
	}
}

// WithStdout sets the writer for standard output.
func WithStdout(w io.Writer) Option {
	return func(l *Logger) {
		l.stdOut = w
	}
}

// WithOutput sets both standard and error output writers.
func WithOutput(stdOut, errOut io.Writer) Option {
	return func(l *Logger) {
		l.stdOut = stdOut
		l.errOut = errOut
	}
}

// New creates a new Logger with the provided options.
func New(opts ...Option) *Logger {
	logger := &Logger{
		verbose: false,
		errOut:  os.Stderr,
		stdOut:  os.Stdout,
	}

	for _, opt := range opts {
		opt(logger)
	}

	return logger
}

// SetVerbose toggles verbose output on this logger. Intended for callers
// that must construct the logger before knowing the desired verbosity
// (e.g. when the flag is not yet parsed).
func (l *Logger) SetVerbose(verbose bool) {
	l.verbose = verbose
}

// Printf formats and writes a message to the error output (only in verbose mode).
func (l *Logger) Printf(format string, a ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintf(l.errOut, format, a...)
	}
}

// Println writes a message to the error output (only in verbose mode).
func (l *Logger) Println(a ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintln(l.errOut, a...)
	}
}

// Errorf writes a formatted error message to the error output (always).
func (l *Logger) Errorf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(l.errOut, format, a...)
}

// Errorln writes an error message to the error output (always).
func (l *Logger) Errorln(a ...interface{}) {
	_, _ = fmt.Fprintln(l.errOut, a...)
}

// Outputf writes formatted output to stdout (always).
func (l *Logger) Outputf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(l.stdOut, format, args...)
}

// Outputln writes line output to stdout (always).
func (l *Logger) Outputln(args ...interface{}) {
	_, _ = fmt.Fprintln(l.stdOut, args...)
}

// Verbosef writes formatted output to stdout (only in verbose mode)
func (l *Logger) Verbosef(format string, args ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintf(l.stdOut, format, args...)
	}
}

// Verboseln writes line output to stdout (only in verbose mode)
func (l *Logger) Verboseln(args ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintln(l.stdOut, args...)
	}
}
