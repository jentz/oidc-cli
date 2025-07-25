package webflow

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"html/template"
	"time"

	"github.com/jentz/oidc-cli/log"
)

//go:embed html/*
var content embed.FS

type CallbackServer struct {
	host     string
	path     string
	server   *http.Server
	response chan *CallbackResponse
	// listen is the function to create a network listener. If nil, defaults to net.Listen.
	// This field allows for dependency injection in tests.
	listen      func(network, addr string) (net.Listener, error)
	successTmpl *template.Template
	errorTmpl   *template.Template
}

type CallbackResponse struct {
	Code             string
	State            string
	ErrorMsg         string
	ErrorDescription string
}

func NewCallbackServer(callbackURI string) (*CallbackServer, error) {
	u, err := url.Parse(callbackURI)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URI: %w", err)
	}

	successTmpl, err := template.ParseFS(content, "html/callback-success.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse success template: %w", err)
	}

	errorTmpl, err := template.ParseFS(content, "html/callback-error.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse error template: %w", err)
	}

	return &CallbackServer{
		host:        u.Host,
		path:        u.Path,
		response:    make(chan *CallbackResponse, 1),
		listen:      net.Listen,
		successTmpl: successTmpl,
		errorTmpl:   errorTmpl,
	}, nil
}

func (s *CallbackServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleCallback)

	s.server = &http.Server{
		Addr:        s.host,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}

	// Create a listener first to ensure we can bind to the port
	listener, err := s.listen("tcp", s.host)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.host, err)
	}

	// Channel to catch server errors
	errChan := make(chan error, 1)
	go func() {
		errChan <- s.server.Serve(listener)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		// Initiate graceful shutdown
		return s.server.Shutdown(context.Background())
	case err := <-errChan:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *CallbackServer) WaitForCallback(ctx context.Context) (*CallbackResponse, error) {
	select {
	case resp := <-s.response:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, errors.New("timeout waiting for callback")
	}
}

func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	var resp CallbackResponse
	var tmpl *template.Template

	resp.Code = r.URL.Query().Get("code")
	resp.State = r.URL.Query().Get("state")
	resp.ErrorMsg = r.URL.Query().Get("error")
	resp.ErrorDescription = r.URL.Query().Get("error_description")

	if resp.Code == "" {
		tmpl = s.errorTmpl
		w.WriteHeader(http.StatusBadRequest)
	} else {
		tmpl = s.successTmpl
		w.WriteHeader(http.StatusOK)
	}

	if err := tmpl.Execute(w, resp); err != nil {
		log.Errorf("failed to execute template: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	select {
	case s.response <- &resp:
		// Successfully sent the response
	default:
		log.Errorf("callback response channel is full, dropping response")
	}
}
