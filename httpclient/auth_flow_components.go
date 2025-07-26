package httpclient

import (
	"context"

	"github.com/jentz/oidc-cli/webflow"
)

// CallbackServerManager handles the lifecycle of callback servers for OAuth flows.
type CallbackServerManager interface {
	// StartServer creates and starts a callback server, returning it for later use.
	StartServer(ctx context.Context, callback string) (*webflow.CallbackServer, error)
	// WaitForCallback waits for the OAuth callback response from the server.
	WaitForCallback(ctx context.Context, server *webflow.CallbackServer) (*webflow.CallbackResponse, error)
}

// AuthorizationURLBuilder constructs OAuth authorization URLs.
type AuthorizationURLBuilder interface {
	// BuildAuthorizationURL creates a complete authorization URL from the endpoint and request parameters.
	BuildAuthorizationURL(endpoint string, req *AuthorizationCodeRequest) (string, error)
}

// BrowserLauncher opens URLs in the user's default browser.
type BrowserLauncher interface {
	// OpenURL opens the specified URL in the system's default browser.
	OpenURL(url string) error
}

// ResponseValidator validates and transforms OAuth callback responses.
type ResponseValidator interface {
	// ValidateResponse validates the callback response and returns the authorization code response.
	ValidateResponse(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error)
}

// AuthFlowDependencies holds all the dependencies needed for authorization code flow.
type AuthFlowDependencies struct {
	ServerManager     CallbackServerManager
	URLBuilder        AuthorizationURLBuilder
	BrowserLauncher   BrowserLauncher
	ResponseValidator ResponseValidator
}

// NewAuthFlowDependencies creates a new set of dependencies with default implementations.
func NewAuthFlowDependencies() *AuthFlowDependencies {
	return &AuthFlowDependencies{
		ServerManager:     &DefaultCallbackServerManager{},
		URLBuilder:        &DefaultAuthorizationURLBuilder{},
		BrowserLauncher:   NewDefaultBrowserLauncher(),
		ResponseValidator: &DefaultResponseValidator{},
	}
}
