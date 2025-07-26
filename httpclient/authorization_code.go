package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/jentz/oidc-cli/log"
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
	// Start the callback server
	server, err := c.authDeps.ServerManager.StartServer(ctx, callback)
	if err != nil {
		return nil, err // Error already wrapped by ServerManager
	}

	// Build the authorization URL
	requestURL, err := c.authDeps.URLBuilder.BuildAuthorizationURL(endpoint, req)
	if err != nil {
		return nil, err // Error already wrapped by URLBuilder
	}
	log.Printf("authorization request: %s\n", requestURL)

	// Open the URL in the browser
	err = c.authDeps.BrowserLauncher.OpenURL(requestURL)
	if err != nil {
		log.Errorf("unable to open browser because %v, visit %s to continue\n", err, requestURL)
	}

	// Wait for the callback response
	callbackResp, err := c.authDeps.ServerManager.WaitForCallback(ctx, server)
	if err != nil {
		return nil, err // Error already wrapped by ServerManager
	}

	// Validate and transform the response
	authResp, err := c.authDeps.ResponseValidator.ValidateResponse(req, callbackResp)
	if err != nil {
		return nil, err // Error already wrapped by ResponseValidator
	}

	return authResp, nil
}
