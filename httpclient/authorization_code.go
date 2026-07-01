package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jentz/oidc-cli/webflow"
)

const (
	defaultServerStartupTimeout = 2 * time.Second        // Callback server startup-detection timeout
	defaultStartDelay           = 100 * time.Millisecond // Delay before treating the server as started
)

type AuthorizationCodeRequest struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Prompt              string
	AcrValues           string
	LoginHint           string
	MaxAge              string
	UILocales           string
	CodeChallengeMethod string
	CodeChallenge       string
	RequestURI          string
	CustomArgs          *CustomArgs
}

type AuthorizationCodeResponse struct {
	Code  string
	State string
}

// CreateAuthorizationCodeRequestValues builds the authorization request URI.
func CreateAuthorizationCodeRequestValues(req *AuthorizationCodeRequest) (*url.Values, error) {
	values := &url.Values{}
	values.Set("response_type", "code")

	// Add required parameters
	if req.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	values.Set("client_id", req.ClientID)

	// Add standard params if set
	if req.State != "" {
		values.Set("state", req.State)
	}
	if req.RedirectURI != "" {
		values.Set("redirect_uri", req.RedirectURI)
	}
	if req.Scope != "" {
		values.Set("scope", req.Scope)
	}
	if req.Prompt != "" {
		values.Set("prompt", req.Prompt)
	}
	if req.AcrValues != "" {
		values.Set("acr_values", req.AcrValues)
	}
	if req.LoginHint != "" {
		values.Set("login_hint", req.LoginHint)
	}
	if req.MaxAge != "" {
		values.Set("max_age", req.MaxAge)
	}
	if req.UILocales != "" {
		values.Set("ui_locales", req.UILocales)
	}
	if req.CodeChallengeMethod != "" {
		values.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.CodeChallenge != "" {
		values.Set("code_challenge", req.CodeChallenge)
	}
	if req.RequestURI != "" {
		values.Set("request_uri", req.RequestURI)
	}

	// Add custom args
	if req.CustomArgs != nil {
		for k, v := range *req.CustomArgs {
			values.Set(k, v)
		}
	}

	return values, nil
}

func CreateAuthorizationCodeRequestURL(endpoint string, values *url.Values) (string, error) {
	if endpoint == "" {
		return "", errors.New("endpoint is required")
	}
	if values == nil {
		return "", errors.New("values cannot be nil")
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse endpoint URL: %w", err)
	}
	endpointURL.RawQuery = values.Encode()
	return endpointURL.String(), nil
}

// ExecuteAuthorizationCodeRequest starts the callback server, opens the
// authorization URL, waits for the redirect, and validates code and state.
func (c *Client) ExecuteAuthorizationCodeRequest(ctx context.Context, endpoint, callback string, req *AuthorizationCodeRequest) (*AuthorizationCodeResponse, error) {
	server, err := c.startCallbackServer(ctx, callback)
	if err != nil {
		return nil, err
	}

	requestURL, err := buildAuthorizationURL(endpoint, req)
	if err != nil {
		return nil, err
	}
	c.logger.Printf("authorization request: %s\n", requestURL)

	if err := c.OpenURL(requestURL); err != nil {
		c.logger.Errorf("unable to open browser because %v, visit %s to continue\n", err, requestURL)
	}

	callbackResp, err := server.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback failed: %w", err)
	}

	return validateCallbackResponse(req, callbackResp)
}

// startCallbackServer starts the callback server in the background, returning
// once it is listening or failing fast on a startup error or timeout.
func (c *Client) startCallbackServer(ctx context.Context, callback string) (*webflow.CallbackServer, error) {
	if callback == "" {
		return nil, errors.New("callback URL is required")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	server, err := webflow.NewCallbackServer(callback, c.logger, webflow.WithListenFunc(c.listen))
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	startupCtx, cancel := context.WithTimeout(ctx, defaultServerStartupTimeout)
	defer cancel()

	serverErrChan := make(chan error, 1)
	go func() {
		// Serve on the parent ctx for the whole flow, not the startup window.
		if err := server.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	select {
	case err := <-serverErrChan:
		return nil, fmt.Errorf("callback server failed to start: %w", err)
	case <-startupCtx.Done():
		return nil, fmt.Errorf("server startup timed out after %v", defaultServerStartupTimeout)
	case <-time.After(defaultStartDelay):
		return server, nil
	}
}

// buildAuthorizationURL renders the authorization request as a full URL.
func buildAuthorizationURL(endpoint string, req *AuthorizationCodeRequest) (string, error) {
	if endpoint == "" {
		return "", errors.New("endpoint is required")
	}
	if req == nil {
		return "", errors.New("request cannot be nil")
	}

	values, err := CreateAuthorizationCodeRequestValues(req)
	if err != nil {
		return "", fmt.Errorf("failed to create authorization request values: %w", err)
	}

	requestURL, err := CreateAuthorizationCodeRequestURL(endpoint, values)
	if err != nil {
		return "", fmt.Errorf("failed to create authorization request URL: %w", err)
	}

	return requestURL, nil
}

// validateCallbackResponse checks the redirect's state (CSRF defense) and that
// an authorization code is present.
func validateCallbackResponse(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if resp == nil {
		return nil, errors.New("response cannot be nil")
	}

	// Reject a mismatched state to prevent CSRF.
	if req.State != "" && resp.State != req.State {
		return nil, fmt.Errorf("state mismatch: expected %q but got %q", req.State, resp.State)
	}

	if resp.Code == "" {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", resp.ErrorMsg, resp.ErrorDescription)
	}

	return &AuthorizationCodeResponse{
		Code:  resp.Code,
		State: req.State,
	}, nil
}
