package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jentz/oidc-cli/webflow"
)

// DefaultCallbackServerManager implements CallbackServerManager using the existing server logic.
type DefaultCallbackServerManager struct{}

// Ensure DefaultCallbackServerManager implements the interface.
var _ CallbackServerManager = (*DefaultCallbackServerManager)(nil)

const (
	defaultServerTimeout = 5 * time.Minute        // Default timeout for server startup
	defaultStartDelay    = 100 * time.Millisecond // Delay to allow server to start
)

// StartServer creates and starts a callback server, returning it for later use.
func (m *DefaultCallbackServerManager) StartServer(ctx context.Context, callback string) (*webflow.CallbackServer, error) {
	if callback == "" {
		return nil, errors.New("callback URL is required")
	}

	callbackServer, err := webflow.NewCallbackServer(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	// Create a timeout context for server startup
	startupCtx, cancel := context.WithTimeout(ctx, defaultServerTimeout)
	defer cancel()

	serverErrChan := make(chan error, 1)
	go func() {
		if err := callbackServer.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	// Give the server a moment to start or fail
	select {
	case err := <-serverErrChan:
		return nil, fmt.Errorf("callback server failed to start: %w", err)
	case <-startupCtx.Done():
		return nil, startupCtx.Err()
	case <-time.After(defaultStartDelay):
		// Server started successfully
		return callbackServer, nil
	}
}

// WaitForCallback waits for the OAuth callback response from the server.
func (m *DefaultCallbackServerManager) WaitForCallback(ctx context.Context, server *webflow.CallbackServer) (*webflow.CallbackResponse, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}

	callbackResp, err := server.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback failed: %w", err)
	}

	return callbackResp, nil
}
