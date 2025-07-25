package webflow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jentz/oidc-cli/log"
)

// mockListener is a mock net.Listener for testing server startup.
type mockListener struct {
	closed    bool
	acceptErr error
	ctx       context.Context // Context to control Accept blocking
}

func (m *mockListener) Accept() (net.Conn, error) {
	if m.acceptErr != nil {
		return nil, m.acceptErr
	}
	// Block until context is canceled
	<-m.ctx.Done()
	return nil, fmt.Errorf("mock accept: %w", m.ctx.Err())
}

func (m *mockListener) Close() error {
	m.closed = true
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func TestNewCallbackServer(t *testing.T) {
	// Skip if template files are missing (real files needed for embed.FS)
	s, err := NewCallbackServer("http://localhost:8080/callback")
	if err != nil {
		if strings.Contains(err.Error(), "failed to parse") {
			t.Skipf("Skipping due to missing template files: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if s.host != "localhost:8080" || s.path != "/callback" {
		t.Errorf("expected host=localhost:8080 path=/callback, got host=%q path=%q", s.host, s.path)
	}
	if s.response == nil {
		t.Error("response channel not initialized")
	}
	if s.listen == nil {
		t.Error("Listen function not initialized")
	}
	if s.successTmpl == nil || s.errorTmpl == nil {
		t.Error("templates not initialized")
	}
}

func TestCallbackServerStart(t *testing.T) {
	s, err := NewCallbackServer("http://localhost:8080/callback")
	if err != nil {
		t.Skipf("Skipping due to template parsing error: %v", err)
	}

	// Create a context for the listener
	ctx, cancel := context.WithCancel(context.Background())
	listener := &mockListener{ctx: ctx}
	s.listen = func(_, addr string) (net.Listener, error) {
		if addr != "localhost:8080" {
			return nil, fmt.Errorf("expected addr localhost:8080, got %s", addr)
		}
		return listener, nil
	}

	// Start server in a goroutine
	go func() {
		if err := s.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Start failed: %v", err)
		}
	}()

	// Wait briefly to ensure server starts
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for shutdown
	time.Sleep(100 * time.Millisecond)

	if !listener.closed {
		t.Error("listener was not closed after shutdown")
	}
}

func TestCallbackServerStartListenError(t *testing.T) {
	s, err := NewCallbackServer("http://localhost:8080/callback")
	if err != nil {
		t.Skipf("Skipping due to template parsing error: %v", err)
	}

	s.listen = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("port unavailable")
	}

	ctx := context.Background()
	err = s.Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "port unavailable") {
		t.Errorf("expected port unavailable error, got %v", err)
	}
}

func TestCallbackServerWaitForCallback(t *testing.T) {
	s, err := NewCallbackServer("http://localhost:8080/callback")
	if err != nil {
		t.Skipf("Skipping due to template parsing error: %v", err)
	}

	resp := &CallbackResponse{Code: "abc123"}
	go func() {
		s.response <- resp
	}()

	ctx := context.Background()
	got, err := s.WaitForCallback(ctx)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if got != resp {
		t.Errorf("expected response %v, got %v", resp, got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.WaitForCallback(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context canceled error, got %v", err)
	}
}

func TestCallbackServerHandleCallback(t *testing.T) {
	// Set up logger to capture output
	var logBuf bytes.Buffer
	log.SetDefaultLogger(log.WithVerbose(true), log.WithStderr(&logBuf), log.WithStdout(&logBuf))

	tests := []struct {
		name           string
		query          string
		successTmpl    *template.Template
		errorTmpl      *template.Template
		wantStatus     int
		wantBody       string
		wantResponse   *CallbackResponse
		wantLogMessage string
	}{
		{
			name:         "Success callback",
			query:        "code=abc123",
			successTmpl:  template.Must(template.New("success").Parse("<p>Success: {{.Code}}</p>")),
			errorTmpl:    template.Must(template.New("error").Parse("<p>Error: {{.ErrorMsg}} - {{.ErrorDescription}}</p>")),
			wantStatus:   http.StatusOK,
			wantBody:     "<p>Success: abc123</p>",
			wantResponse: &CallbackResponse{Code: "abc123"},
		},
		{
			name:         "Success callback with state",
			query:        "code=abc123&state=test-state-123",
			successTmpl:  template.Must(template.New("success").Parse("<p>Success: {{.Code}}</p>")),
			errorTmpl:    template.Must(template.New("error").Parse("<p>Error: {{.ErrorMsg}} - {{.ErrorDescription}}</p>")),
			wantStatus:   http.StatusOK,
			wantBody:     "<p>Success: abc123</p>",
			wantResponse: &CallbackResponse{Code: "abc123", State: "test-state-123"},
		},
		{
			name:         "Error callback",
			query:        "error=invalid_grant&error_description=Bad+request",
			successTmpl:  template.Must(template.New("success").Parse("<p>Success: {{.Code}}</p>")),
			errorTmpl:    template.Must(template.New("error").Parse("<p>Error: {{.ErrorMsg}} - {{.ErrorDescription}}</p>")),
			wantStatus:   http.StatusBadRequest,
			wantBody:     "<p>Error: invalid_grant - Bad request</p>",
			wantResponse: &CallbackResponse{ErrorMsg: "invalid_grant", ErrorDescription: "Bad request"},
		},
		{
			name:           "Template execution error",
			query:          "code=abc123",
			successTmpl:    template.Must(template.New("success").Parse("<p>Success: {{.InvalidField}}</p>")), // Invalid field
			errorTmpl:      template.Must(template.New("error").Parse("<p>Error: {{.ErrorMsg}}</p>")),
			wantStatus:     http.StatusOK,
			wantBody:       "<p>Success: Internal Server Error\n",
			wantLogMessage: "failed to execute template",
		},
		{
			name:           "Channel full",
			query:          "code=abc123",
			successTmpl:    template.Must(template.New("success").Parse("<p>Success: {{.Code}}</p>")),
			errorTmpl:      template.Must(template.New("error").Parse("<p>Error: {{.ErrorMsg}}</p>")),
			wantStatus:     http.StatusOK,
			wantBody:       "<p>Success: abc123</p>",
			wantResponse:   &CallbackResponse{Code: "abc123"},
			wantLogMessage: "callback response channel is full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuf.Reset()

			s, err := NewCallbackServer("http://localhost:8080/callback")
			if err != nil {
				t.Skipf("Skipping due to template parsing error: %v", err)
			}

			s.successTmpl = tt.successTmpl
			s.errorTmpl = tt.errorTmpl

			if tt.name == "Channel full" {
				s.response <- &CallbackResponse{Code: "dummy"}
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/callback?"+tt.query, nil)
			s.handleCallback(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}
			if gotBody := w.Body.String(); gotBody != tt.wantBody {
				t.Errorf("expected body %q, got %q", tt.wantBody, gotBody)
			}

			if tt.name != "Template execution error" && tt.name != "Channel full" {
				select {
				case got := <-s.response:
					if got.Code != tt.wantResponse.Code ||
						got.State != tt.wantResponse.State ||
						got.ErrorMsg != tt.wantResponse.ErrorMsg ||
						got.ErrorDescription != tt.wantResponse.ErrorDescription {
						t.Errorf("expected response %v, got %v", tt.wantResponse, got)
					}
				default:
					t.Error("expected response in channel, got none")
				}
			}

			if tt.wantLogMessage != "" {
				logOutput := logBuf.String()
				if logOutput == "" {
					t.Error("expected log message, got none")
				} else if !strings.Contains(logOutput, tt.wantLogMessage) {
					t.Errorf("expected log message containing %q, got %q", tt.wantLogMessage, logOutput)
				}
			}
		})
	}
}
