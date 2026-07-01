package httpclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
)

const (
	IntrospectResponseDefaultMediaType = "application/json"
)

type IntrospectionRequest struct {
	Token           string
	TokenTypeHint   string
	CustomArgs      *CustomArgs
	AuthMethod      AuthMethod
	ClientID        string
	ClientSecret    string
	BearerToken     string
	AcceptMediaType string
}

func (c *Client) ExecuteIntrospectionRequest(ctx context.Context, endpoint string, req *IntrospectionRequest, headers map[string]string) (*Response, error) {
	if headers == nil {
		headers = make(map[string]string)
	}

	// Set the token in the request body
	params := url.Values{}
	params.Set("token", req.Token)
	if req.TokenTypeHint != "" {
		params.Set("token_type_hint", req.TokenTypeHint)
	}
	// Add custom args
	if req.CustomArgs != nil {
		for k, v := range *req.CustomArgs {
			params.Set(k, v)
		}
	}

	// Apply authentication method
	switch req.AuthMethod {
	case AuthMethodBasic:
		// Use HTTP Basic Auth
		auth := base64.StdEncoding.EncodeToString([]byte(req.ClientID + ":" + req.ClientSecret))
		headers["Authorization"] = "Basic " + auth
	case AuthMethodPost:
		// Include credentials in request body
		params.Set("client_id", req.ClientID)
		if req.ClientSecret != "" {
			params.Set("client_secret", req.ClientSecret)
		}
	case AuthMethodNone:
		// Just include client_id in request body
		params.Set("client_id", req.ClientID)
	}

	// Set the Accept header if specified
	if req.AcceptMediaType != "" {
		headers["Accept"] = req.AcceptMediaType
	} else {
		// Default to JSON if not specified
		headers["Accept"] = IntrospectResponseDefaultMediaType
	}

	// Execute the request
	return c.PostForm(ctx, endpoint, params, headers)
}

// ParseIntrospectionResponse parses the introspection response into a map
func ParseIntrospectionResponse(resp *Response) (map[string]any, error) {
	var mapResp map[string]any

	// Try to parse JSON regardless of status code
	if err := resp.JSON(&mapResp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsingJSON, err)
	}

	if !resp.IsSuccess() {
		oauth2Err := &Error{
			StatusCode: resp.StatusCode,
			RawBody:    resp.String(),
		}

		// Extract standard OAuth2 error fields if present
		if errStr, ok := mapResp["error"].(string); ok {
			oauth2Err.ErrorType = errStr
			if desc, ok := mapResp["error_description"].(string); ok {
				oauth2Err.ErrorDescription = desc
			}
			return mapResp, fmt.Errorf("%w: %w", ErrOAuthError, oauth2Err)
		}

		return nil, oauth2Err
	}

	return mapResp, nil
}
