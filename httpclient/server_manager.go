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
	defaultServerStartupTimeout = 2 * time.Second        // Timeout for server startup detection
	defaultStartDelay           = 100 * time.Millisecond // Delay to allow server to start
)

// StartServer creates and starts a callback server, returning it for later use.
func (m *DefaultCallbackServerManager) StartServer(ctx context.Context, callback string) (*webflow.CallbackServer, error) {
	if callback == "" {
		return nil, errors.New("callback URL is required")
	}

	// Check if the parent context is already cancelled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	callbackServer, err := webflow.NewCallbackServer(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	// Create a short timeout context for startup detection that respects parent cancellation
	startupCtx, cancel := context.WithTimeout(ctx, defaultServerStartupTimeout)
	defer cancel()

	serverErrChan := make(chan error, 1)
	go func() {
		// Server runs with original context for full flow duration
		if err := callbackServer.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	// Wait for startup success/failure with SHORT timeout
	select {
	case err := <-serverErrChan:
		return nil, fmt.Errorf("callback server failed to start: %w", err)
	case <-startupCtx.Done():
		return nil, fmt.Errorf("server startup timed out after %v", defaultServerStartupTimeout)
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
