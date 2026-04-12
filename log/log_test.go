package log

import (
	"bytes"
	"strings"
	"testing"
)

// Helper function to create a logger with captured output
func setupTestLogger(verbose bool) (*Logger, *bytes.Buffer, *bytes.Buffer) {
	var errBuf, outBuf bytes.Buffer
	logger := New(
		WithVerbose(verbose),
		WithOutput(&outBuf, &errBuf),
	)
	return logger, &errBuf, &outBuf
}

func TestVerboseLogging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		verbose bool
		logFunc func(*Logger)
		wantErr string
		wantOut string
	}{
		{
			name:    "Printf with verbose=true",
			verbose: true,
			logFunc: func(l *Logger) { l.Printf("test %s", "message") },
			wantErr: "test message",
			wantOut: "",
		},
		{
			name:    "Printf with verbose=false",
			verbose: false,
			logFunc: func(l *Logger) { l.Printf("test %s", "message") },
			wantErr: "",
			wantOut: "",
		},
		{
			name:    "Println with verbose=true",
			verbose: true,
			logFunc: func(l *Logger) { l.Println("test", "message") },
			wantErr: "test message\n",
			wantOut: "",
		},
		{
			name:    "Println with verbose=false",
			verbose: false,
			logFunc: func(l *Logger) { l.Println("test", "message") },
			wantErr: "",
			wantOut: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, errBuf, outBuf := setupTestLogger(tt.verbose)
			tt.logFunc(logger)

			if got := errBuf.String(); got != tt.wantErr {
				t.Errorf("stderr = %q, want %q", got, tt.wantErr)
			}
			if got := outBuf.String(); got != tt.wantOut {
				t.Errorf("stdout = %q, want %q", got, tt.wantOut)
			}
		})
	}
}

func TestErrorLogging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		verbose bool // should not affect error logging
		logFunc func(*Logger)
		wantErr string
	}{
		{
			name:    "Errorf always prints (verbose=true)",
			verbose: true,
			logFunc: func(l *Logger) { l.Errorf("error: %s", "something wrong") },
			wantErr: "error: something wrong",
		},
		{
			name:    "Errorf always prints (verbose=false)",
			verbose: false,
			logFunc: func(l *Logger) { l.Errorf("error: %s", "something wrong") },
			wantErr: "error: something wrong",
		},
		{
			name:    "Errorln always prints (verbose=true)",
			verbose: true,
			logFunc: func(l *Logger) { l.Errorln("error", "message") },
			wantErr: "error message\n",
		},
		{
			name:    "Errorln always prints (verbose=false)",
			verbose: false,
			logFunc: func(l *Logger) { l.Errorln("error", "message") },
			wantErr: "error message\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, errBuf, outBuf := setupTestLogger(tt.verbose)
			tt.logFunc(logger)

			if got := errBuf.String(); got != tt.wantErr {
				t.Errorf("stderr = %q, want %q", got, tt.wantErr)
			}
			if got := outBuf.String(); got != "" {
				t.Errorf("stdout should be empty, got %q", got)
			}
		})
	}
}

func TestOutputLogging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		verbose bool // should not affect output logging
		logFunc func(*Logger)
		wantOut string
	}{
		{
			name:    "Outputf always prints (verbose=true)",
			verbose: true,
			logFunc: func(l *Logger) { l.Outputf("result: %d", 42) },
			wantOut: "result: 42",
		},
		{
			name:    "Outputf always prints (verbose=false)",
			verbose: false,
			logFunc: func(l *Logger) { l.Outputf("result: %d", 42) },
			wantOut: "result: 42",
		},
		{
			name:    "Outputln always prints (verbose=true)",
			verbose: true,
			logFunc: func(l *Logger) { l.Outputln("result", "data") },
			wantOut: "result data\n",
		},
		{
			name:    "Outputln always prints (verbose=false)",
			verbose: false,
			logFunc: func(l *Logger) { l.Outputln("result", "data") },
			wantOut: "result data\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, errBuf, outBuf := setupTestLogger(tt.verbose)
			tt.logFunc(logger)

			if got := outBuf.String(); got != tt.wantOut {
				t.Errorf("stdout = %q, want %q", got, tt.wantOut)
			}
			if got := errBuf.String(); got != "" {
				t.Errorf("stderr should be empty, got %q", got)
			}
		})
	}
}

func TestVerboseOutputLogging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		verbose bool
		logFunc func(*Logger)
		wantOut string
	}{
		{
			name:    "Verbosef with verbose=true",
			verbose: true,
			logFunc: func(l *Logger) { l.Verbosef("detail: %s", "info") },
			wantOut: "detail: info",
		},
		{
			name:    "Verbosef with verbose=false",
			verbose: false,
			logFunc: func(l *Logger) { l.Verbosef("detail: %s", "info") },
			wantOut: "",
		},
		{
			name:    "Verboseln with verbose=true",
			verbose: true,
			logFunc: func(l *Logger) { l.Verboseln("verbose", "output") },
			wantOut: "verbose output\n",
		},
		{
			name:    "Verboseln with verbose=false",
			verbose: false,
			logFunc: func(l *Logger) { l.Verboseln("verbose", "output") },
			wantOut: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, errBuf, outBuf := setupTestLogger(tt.verbose)
			tt.logFunc(logger)

			if got := outBuf.String(); got != tt.wantOut {
				t.Errorf("stdout = %q, want %q", got, tt.wantOut)
			}
			if got := errBuf.String(); got != "" {
				t.Errorf("stderr should be empty, got %q", got)
			}
		})
	}
}

func TestFunctionalOptions(t *testing.T) {
	t.Parallel()
	t.Run("default logger", func(t *testing.T) {
		t.Parallel()
		logger := New()
		if logger.verbose {
			t.Error("default logger should not be verbose")
		}
		if logger.errOut == nil || logger.stdOut == nil {
			t.Error("default logger should have non-nil writers")
		}
	})

	t.Run("with verbose option", func(t *testing.T) {
		t.Parallel()
		logger := New(WithVerbose(true))
		if !logger.verbose {
			t.Error("logger should be verbose")
		}
	})

	t.Run("with custom writers", func(t *testing.T) {
		t.Parallel()
		var errBuf, outBuf bytes.Buffer
		logger := New(WithOutput(&outBuf, &errBuf))

		logger.Errorf("error")
		logger.Outputf("output")

		if errBuf.String() != "error" {
			t.Errorf("custom stderr writer not working: got %q", errBuf.String())
		}
		if outBuf.String() != "output" {
			t.Errorf("custom stdout writer not working: got %q", outBuf.String())
		}
	})

	t.Run("multiple options", func(t *testing.T) {
		t.Parallel()
		var errBuf, outBuf bytes.Buffer
		logger := New(
			WithVerbose(true),
			WithStderr(&errBuf),
			WithStdout(&outBuf),
		)

		logger.Printf("debug")
		logger.Outputf("result")

		if errBuf.String() != "debug" {
			t.Errorf("verbose stderr not working: got %q", errBuf.String())
		}
		if outBuf.String() != "result" {
			t.Errorf("stdout not working: got %q", outBuf.String())
		}
	})
}

func TestDiscard(t *testing.T) {
	t.Parallel()
	logger := Discard()
	if logger == nil {
		t.Fatal("Discard() returned nil")
	}

	logger.Printf("should not panic")
	logger.Errorf("should not panic")
	logger.Outputf("should not panic")
	logger.Verbosef("should not panic")

	if Discard() == logger {
		t.Error("Discard() should return a new instance each call")
	}
}

func TestSetVerbose(t *testing.T) {
	t.Parallel()
	var errBuf bytes.Buffer
	logger := New(WithVerbose(false), WithStderr(&errBuf))

	logger.Printf("hidden")
	if errBuf.Len() != 0 {
		t.Errorf("expected no output with verbose=false, got %q", errBuf.String())
	}

	logger.SetVerbose(true)
	logger.Printf("visible")
	if got := errBuf.String(); got != "visible" {
		t.Errorf("expected %q after SetVerbose(true), got %q", "visible", got)
	}

	errBuf.Reset()
	logger.SetVerbose(false)
	logger.Printf("hidden again")
	if errBuf.Len() != 0 {
		t.Errorf("expected no output after SetVerbose(false), got %q", errBuf.String())
	}
}

func TestComplexScenario(t *testing.T) {
	t.Parallel()
	// Test a realistic CLI scenario
	logger, errBuf, outBuf := setupTestLogger(true)

	// Simulate processing files
	files := []string{"file1.txt", "file2.txt"}

	logger.Printf("Starting to process %d files", len(files))
	for i, file := range files {
		logger.Printf("Processing: %s", file)
		logger.Outputf("Processed %s (%d/%d)", file, i+1, len(files))
		if i == 1 {
			logger.Errorf("Warning: %s has issues", file)
		}
	}
	logger.Verboseln("All processing complete with detailed stats")

	errOutput := errBuf.String()
	outOutput := outBuf.String()

	// Check stderr contains debug info and errors
	expectedErrParts := []string{
		"Starting to process 2 files",
		"Processing: file1.txt",
		"Processing: file2.txt",
		"Warning: file2.txt has issues",
	}
	for _, part := range expectedErrParts {
		if !strings.Contains(errOutput, part) {
			t.Errorf("stderr missing %q, got: %q", part, errOutput)
		}
	}

	// Check stdout contains results
	expectedOutParts := []string{
		"Processed file1.txt (1/2)",
		"Processed file2.txt (2/2)",
		"All processing complete with detailed stats",
	}
	for _, part := range expectedOutParts {
		if !strings.Contains(outOutput, part) {
			t.Errorf("stdout missing %q, got: %q", part, outOutput)
		}
	}
}

// Benchmark tests
func BenchmarkLogging(b *testing.B) {
	logger, _, _ := setupTestLogger(true)

	b.Run("Printf", func(b *testing.B) {
		for b.Loop() {
			logger.Printf("benchmark message")
		}
	})

	b.Run("Outputf", func(b *testing.B) {
		for b.Loop() {
			logger.Outputf("result message")
		}
	})

	b.Run("Printf_disabled", func(b *testing.B) {
		quietLogger, _, _ := setupTestLogger(false)
		for b.Loop() {
			quietLogger.Printf("benchmark message")
		}
	})
}
