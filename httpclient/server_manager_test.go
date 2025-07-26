package httpclient

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jentz/oidc-cli/webflow"
)

func TestDefaultCallbackServerManager_StartServer(t *testing.T) {
	manager := &DefaultCallbackServerManager{}

	tests := []struct {
		name        string
		callback    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid callback URL",
			callback: "http://localhost:0/callback", // Use port 0 for any available port
			wantErr:  false,
		},
		{
			name:        "empty callback URL",
			callback:    "",
			wantErr:     true,
			errContains: "callback URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			server, err := manager.StartServer(ctx, tt.callback)

			if tt.wantErr {
				if err == nil {
					t.Errorf("StartServer() error = nil, wantErr %v", tt.wantErr)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("StartServer() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("StartServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if server == nil {
				t.Error("StartServer() returned nil server")
			}
		})
	}
}

func TestDefaultCallbackServerManager_StartServer_InvalidURL(t *testing.T) {
	manager := &DefaultCallbackServerManager{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test with a URL that will fail during URL parsing
	server, err := manager.StartServer(ctx, "ht tp://invalid")

	if err == nil {
		t.Error("StartServer() should fail with invalid URL")
	}
	if server != nil {
		t.Error("StartServer() should return nil server on error")
	}
	if !strings.Contains(err.Error(), "failed to create callback server") {
		t.Errorf("StartServer() error should contain 'failed to create callback server', got: %v", err)
	}
}

func TestDefaultCallbackServerManager_StartServer_ContextCanceled(t *testing.T) {
	manager := &DefaultCallbackServerManager{}

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	server, err := manager.StartServer(ctx, "http://localhost:0/callback")

	if err == nil {
		t.Error("StartServer() should fail with canceled context")
	}
	if server != nil {
		t.Error("StartServer() should return nil server on error")
	}
}

func TestDefaultCallbackServerManager_WaitForCallback(t *testing.T) {
	manager := &DefaultCallbackServerManager{}

	tests := []struct {
		name        string
		server      *webflow.CallbackServer
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil server",
			server:      nil,
			wantErr:     true,
			errContains: "server cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			resp, err := manager.WaitForCallback(ctx, tt.server)

			if tt.wantErr {
				if err == nil {
					t.Errorf("WaitForCallback() error = nil, wantErr %v", tt.wantErr)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("WaitForCallback() error = %v, want error containing %v", err, tt.errContains)
				}
				if resp != nil {
					t.Error("WaitForCallback() should return nil response on error")
				}
				return
			}

			if err != nil {
				t.Errorf("WaitForCallback() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultCallbackServerManager_WaitForCallback_Timeout(t *testing.T) {
	manager := &DefaultCallbackServerManager{}

	// Create a server but don't send any callback
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	server, err := manager.StartServer(ctx, "http://localhost:0/callback")
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Create a very short timeout context for waiting
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()

	resp, err := manager.WaitForCallback(waitCtx, server)

	if err == nil {
		t.Error("WaitForCallback() should timeout")
	}
	if resp != nil {
		t.Error("WaitForCallback() should return nil response on timeout")
	}
	if !strings.Contains(err.Error(), "callback failed") {
		t.Errorf("WaitForCallback() error should contain 'callback failed', got: %v", err)
	}
}

func TestDefaultCallbackServerManager_Interface(_ *testing.T) {
	var _ CallbackServerManager = (*DefaultCallbackServerManager)(nil)
}

// Integration test to verify the full server lifecycle
func TestDefaultCallbackServerManager_Integration(t *testing.T) {
	manager := &DefaultCallbackServerManager{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start server
	server, err := manager.StartServer(ctx, "http://localhost:0/callback") // Use port 0 for any available port
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	if server == nil {
		t.Fatal("Server should not be nil")
	}
}
