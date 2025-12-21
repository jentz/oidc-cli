package httpclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	AuthMethod   AuthMethod
	Params       url.Values
}

// TokenExchangeInput is used to construct the parameters of a token exchange request
type TokenExchangeInput struct {
	GrantType          string
	Resource           string
	Audience           string
	Scope              string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
}

// ExecuteTokenRequest sends a token request to the specified endpoint
func (c *Client) ExecuteTokenRequest(ctx context.Context, tokenEndpoint string, req *TokenRequest, headers map[string]string) (*Response, error) {
	if req.Params == nil {
		req.Params = url.Values{}
	}

	if headers == nil {
		headers = make(map[string]string)
	}

	// Set grant type
	req.Params.Set("grant_type", req.GrantType)

	// Apply authentication method
	switch req.AuthMethod {
	case AuthMethodBasic:
		// Use HTTP Basic Auth
		auth := base64.StdEncoding.EncodeToString([]byte(req.ClientID + ":" + req.ClientSecret))
		headers["Authorization"] = "Basic " + auth
	case AuthMethodPost:
		// Include credentials in request body
		req.Params.Set("client_id", req.ClientID)
		if req.ClientSecret != "" {
			req.Params.Set("client_secret", req.ClientSecret)
		}
	case AuthMethodNone:
		// Just include client_id in request body
		req.Params.Set("client_id", req.ClientID)
	}

	// Execute the request
	return c.PostForm(ctx, tokenEndpoint, req.Params, headers)
}

// ExecutePollingTokenRequest sends a token request to the specified endpoint, polling at the specified interval until a successful response is received
func (c *Client) ExecutePollingTokenRequest(ctx context.Context, tokenEndpoint string, req *TokenRequest, interval int) (*Response, error) {
	if interval <= 0 {
		interval = 5 // Default polling interval in seconds
	}

	for {
		resp, err := c.ExecuteTokenRequest(ctx, tokenEndpoint, req, nil)
		if err != nil {
			return nil, err
		}

		if resp.IsSuccess() {
			return resp, nil
		}

		// Parse error response to check for "authorization_pending" or "slow_down"
		oauth2Err := &Error{
			StatusCode: resp.StatusCode,
			RawBody:    resp.String(),
		}
		var mapResp map[string]interface{}

		if err := json.Unmarshal(resp.Body, &mapResp); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrParsingJSON, err)
		}

		if errStr, ok := mapResp["error"].(string); ok {
			oauth2Err.ErrorType = errStr
			if desc, ok := mapResp["error_description"].(string); ok {
				oauth2Err.ErrorDescription = desc
			}

			if oauth2Err.ErrorType == "authorization_pending" {
				// Wait and poll again
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			} else if oauth2Err.ErrorType == "slow_down" {
				// Increase interval and poll again
				interval += 5
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			} else {
				return nil, fmt.Errorf("%w: %v", ErrOAuthError, oauth2Err)
			}
		}

		return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, oauth2Err)
	}
}

// CreateAuthCodeTokenRequest creates a token request for the authorization code grant
func CreateAuthCodeTokenRequest(clientID, clientSecret string, authMethod AuthMethod, code, redirectURI, codeVerifier string) *TokenRequest {
	params := url.Values{}
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}

	return &TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Params:       params,
	}
}

// CreateRefreshTokenRequest creates a token request for the refresh token grant
func CreateRefreshTokenRequest(clientID, clientSecret string, authMethod AuthMethod, refreshToken, scope string) *TokenRequest {
	params := url.Values{}
	params.Set("refresh_token", refreshToken)
	if scope != "" {
		params.Set("scope", scope)
	}

	return &TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Params:       params,
	}
}

// CreateClientCredentialsRequest creates a token request for the client credentials grant
func CreateClientCredentialsRequest(clientID, clientSecret string, authMethod AuthMethod, scope string) *TokenRequest {
	params := url.Values{}
	if scope != "" {
		params.Set("scope", scope)
	}

	return &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Params:       params,
	}
}

// CreateDeviceCodeTokenRequest creates a token request for the device code grant
func CreateDeviceCodeTokenRequest(clientID, clientSecret string, authMethod AuthMethod, deviceCode string) *TokenRequest {
	params := url.Values{}
	params.Set("device_code", deviceCode)

	return &TokenRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:device_code",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Params:       params,
	}
}

// CreateTokenExchangeRequest creates a token request for the token exchange grant
func CreateTokenExchangeRequest(clientID, clientSecret string, authMethod AuthMethod, input TokenExchangeInput) *TokenRequest {
	params := url.Values{}

	// Required parameters
	params.Set("subject_token", input.SubjectToken)
	params.Set("subject_token_type", input.SubjectTokenType)

	// Optional parameters
	if input.Resource != "" {
		params.Set("resource", input.Resource)
	}
	if input.Audience != "" {
		params.Set("audience", input.Audience)
	}
	if input.Scope != "" {
		params.Set("scope", input.Scope)
	}
	if input.RequestedTokenType != "" {
		params.Set("requested_token_type", input.RequestedTokenType)
	}
	if input.ActorToken != "" {
		params.Set("actor_token", input.ActorToken)
	}
	if input.ActorTokenType != "" {
		params.Set("actor_token_type", input.ActorTokenType)
	}

	return &TokenRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Params:       params,
	}
}

// ParseTokenResponse parses the standard OAuth2 token response
func ParseTokenResponse(resp *Response) (map[string]interface{}, error) {
	var tokenResp map[string]interface{}

	// Try to parse JSON regardless of status code
	if err := resp.JSON(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParsingJSON, err)
	}

	// Check if there was an HTTP error
	if !resp.IsSuccess() {
		oauth2Err := &Error{
			StatusCode: resp.StatusCode,
			RawBody:    resp.String(),
		}

		// Extract standard OAuth2 error fields if present
		if errStr, ok := tokenResp["error"].(string); ok {
			oauth2Err.ErrorType = errStr
			if desc, ok := tokenResp["error_description"].(string); ok {
				oauth2Err.ErrorDescription = desc
			}
			return tokenResp, fmt.Errorf("%w: %v", ErrOAuthError, oauth2Err)
		}

		return tokenResp, fmt.Errorf("%w: %v", ErrHTTPFailure, oauth2Err)
	}

	// Success case with valid JSON and 2xx status code
	return tokenResp, nil
}
