package httpclient

import (
	"context"
	"testing"

	"github.com/jentz/oidc-cli/webflow"
)

// MockAuthFlowDependencies creates a set of mock dependencies for testing.
type MockAuthFlowDependencies struct {
	ServerManager     CallbackServerManager
	URLBuilder        AuthorizationURLBuilder
	BrowserLauncher   BrowserLauncher
	ResponseValidator ResponseValidator
}

// MockCallbackServerManager for testing.
type MockCallbackServerManager struct {
	StartServerFunc     func(ctx context.Context, callback string) (*webflow.CallbackServer, error)
	WaitForCallbackFunc func(ctx context.Context, server *webflow.CallbackServer) (*webflow.CallbackResponse, error)
}

func (m *MockCallbackServerManager) StartServer(ctx context.Context, callback string) (*webflow.CallbackServer, error) {
	if m.StartServerFunc != nil {
		return m.StartServerFunc(ctx, callback)
	}
	return nil, nil
}

func (m *MockCallbackServerManager) WaitForCallback(ctx context.Context, server *webflow.CallbackServer) (*webflow.CallbackResponse, error) {
	if m.WaitForCallbackFunc != nil {
		return m.WaitForCallbackFunc(ctx, server)
	}
	return nil, nil
}

// MockAuthorizationURLBuilder for testing.
type MockAuthorizationURLBuilder struct {
	BuildAuthorizationURLFunc func(endpoint string, req *AuthorizationCodeRequest) (string, error)
}

func (m *MockAuthorizationURLBuilder) BuildAuthorizationURL(endpoint string, req *AuthorizationCodeRequest) (string, error) {
	if m.BuildAuthorizationURLFunc != nil {
		return m.BuildAuthorizationURLFunc(endpoint, req)
	}
	return "", nil
}

// MockBrowserLauncher (reusing from browser_launcher_test.go concept)
type MockBrowserLauncherForIntegration struct {
	OpenURLFunc func(url string) error
}

func (m *MockBrowserLauncherForIntegration) OpenURL(url string) error {
	if m.OpenURLFunc != nil {
		return m.OpenURLFunc(url)
	}
	return nil
}

// MockResponseValidator for testing.
type MockResponseValidator struct {
	ValidateResponseFunc func(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error)
}

func (m *MockResponseValidator) ValidateResponse(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error) {
	if m.ValidateResponseFunc != nil {
		return m.ValidateResponseFunc(req, resp)
	}
	return nil, nil
}

// TestExecuteAuthorizationCodeRequest_WithMocks covers the scenario of executing an authorization code request with mocked dependencies.
func TestExecuteAuthorizationCodeRequest_WithMocks(t *testing.T) {
	client := NewClient(nil)

	// Create mock dependencies
	mockDeps := &AuthFlowDependencies{
		ServerManager: &MockCallbackServerManager{
			StartServerFunc: func(_ context.Context, callback string) (*webflow.CallbackServer, error) {
				// Mock server creation - we can verify the callback URL
				if callback != "http://localhost:8080/callback" {
					t.Errorf("Expected callback http://localhost:8080/callback, got %s", callback)
				}
				return &webflow.CallbackServer{}, nil // Return a mock server
			},
			WaitForCallbackFunc: func(_ context.Context, _ *webflow.CallbackServer) (*webflow.CallbackResponse, error) {
				// Mock successful callback response
				return &webflow.CallbackResponse{
					Code:  "test-auth-code",
					State: "test-state",
				}, nil
			},
		},
		URLBuilder: &MockAuthorizationURLBuilder{
			BuildAuthorizationURLFunc: func(endpoint string, req *AuthorizationCodeRequest) (string, error) {
				// Mock URL building - we can verify the parameters
				if endpoint != "https://auth.example.com/authorize" {
					t.Errorf("Expected endpoint https://auth.example.com/authorize, got %s", endpoint)
				}
				if req.ClientID != "test-client" {
					t.Errorf("Expected client ID test-client, got %s", req.ClientID)
				}
				return "https://auth.example.com/authorize?client_id=test-client&response_type=code&state=test-state", nil
			},
		},
		BrowserLauncher: &MockBrowserLauncherForIntegration{
			OpenURLFunc: func(url string) error {
				// Mock browser opening - we can verify the URL
				expectedURL := "https://auth.example.com/authorize?client_id=test-client&response_type=code&state=test-state"
				if url != expectedURL {
					t.Errorf("Expected URL %s, got %s", expectedURL, url)
				}
				return nil
			},
		},
		ResponseValidator: &MockResponseValidator{
			ValidateResponseFunc: func(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error) {
				// Mock response validation - we can verify the validation logic
				if req.State != resp.State {
					t.Errorf("State mismatch: expected %s, got %s", req.State, resp.State)
				}
				return &AuthorizationCodeResponse{
					Code:  resp.Code,
					State: resp.State,
				}, nil
			},
		},
	}

	// Inject the mock dependencies
	client.SetAuthFlowDependencies(mockDeps)

	// Execute the authorization code request
	ctx := context.Background()
	req := &AuthorizationCodeRequest{
		ClientID: "test-client",
		State:    "test-state",
	}

	resp, err := client.ExecuteAuthorizationCodeRequest(ctx, "https://auth.example.com/authorize", "http://localhost:8080/callback", req)

	// Verify the results
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("Response should not be nil")
	}

	if resp.Code != "test-auth-code" {
		t.Errorf("Expected code test-auth-code, got %s", resp.Code)
	}

	if resp.State != "test-state" {
		t.Errorf("Expected state test-state, got %s", resp.State)
	}
}

// TestExecuteAuthorizationCodeRequest_ComponentIsolation demonstrates how individual
// components can be tested in isolation.
func TestExecuteAuthorizationCodeRequest_ComponentIsolation(t *testing.T) {
	client := NewClient(nil)

	// Test scenario: Server manager fails to start server
	mockDeps := &AuthFlowDependencies{
		ServerManager: &MockCallbackServerManager{
			StartServerFunc: func(_ context.Context, _ string) (*webflow.CallbackServer, error) {
				return nil, &Error{
					ErrorType:        "server_error",
					ErrorDescription: "Failed to start callback server",
					StatusCode:       500,
				}
			},
		},
		URLBuilder:        &DefaultAuthorizationURLBuilder{}, // Use real implementation
		BrowserLauncher:   NewDefaultBrowserLauncher(),       // Use real implementation
		ResponseValidator: &DefaultResponseValidator{},       // Use real implementation
	}

	client.SetAuthFlowDependencies(mockDeps)

	ctx := context.Background()
	req := &AuthorizationCodeRequest{
		ClientID: "test-client",
		State:    "test-state",
	}

	_, err := client.ExecuteAuthorizationCodeRequest(ctx, "https://auth.example.com/authorize", "http://localhost:8080/callback", req)

	// Verify that the server error is properly propagated
	if err == nil {
		t.Error("Expected error from server manager, got nil")
	}

	if err.Error() != "error: server_error - Failed to start callback server, status: 500" {
		t.Errorf("Expected server error, got: %v", err)
	}
}
