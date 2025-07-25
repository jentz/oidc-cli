package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/webflow"
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

// ExecuteAuthorizationCodeRequest executes the authorization code request and returns the auth code response.
func (c *Client) ExecuteAuthorizationCodeRequest(ctx context.Context, endpoint string, callback string, req *AuthorizationCodeRequest) (*AuthorizationCodeResponse, error) {
	callbackServer, err := webflow.NewCallbackServer(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
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
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	requestValues, err := CreateAuthorizationCodeRequestValues(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization request values: %w", err)
	}

	requestURL, err := CreateAuthorizationCodeRequestURL(endpoint, requestValues)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization request URL: %w", err)
	}
	log.Printf("authorization request: %s\n", requestURL)

	browser := webflow.NewBrowser()
	err = browser.Open(requestURL)
	if err != nil {
		log.Errorf("unable to open browser because %v, visit %s to continue\n", err, requestURL)
	}

	callbackResp, err := callbackServer.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback failed: %w", err)
	}

	// Validate state parameter to prevent CSRF attacks
	if req.State != "" && callbackResp.State != req.State {
		return nil, fmt.Errorf("state mismatch: expected %q but got %q", req.State, callbackResp.State)
	}

	if callbackResp.Code == "" {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", callbackResp.ErrorMsg, callbackResp.ErrorDescription)
	}

	return &AuthorizationCodeResponse{
		Code:  callbackResp.Code,
		State: callbackResp.State,
	}, nil
}
