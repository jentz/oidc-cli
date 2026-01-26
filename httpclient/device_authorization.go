package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type DeviceAuthorizationRequest struct {
	ClientID            string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// ExecuteDeviceAuthorizationRequest sends a device authorization request to the specified endpoint
func (c *Client) ExecuteDeviceAuthorizationRequest(ctx context.Context, endpoint string, req *DeviceAuthorizationRequest, headers map[string]string) (*Response, error) {
	if headers == nil {
		headers = make(map[string]string)
	}

	params := url.Values{}
	params.Set("client_id", req.ClientID)
	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}
	if req.CodeChallenge != "" {
		params.Set("code_challenge", req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		params.Set("code_challenge_method", req.CodeChallengeMethod)
	}

	// Execute the request
	return c.PostForm(ctx, endpoint, params, headers)
}

// ParseDeviceAuthorizationResponse parses the device authorization response into a map
func ParseDeviceAuthorizationResponse(resp *Response) (*DeviceAuthorizationResponse, error) {
	if !resp.IsSuccess() {
		oauth2Err := &Error{
			StatusCode: resp.StatusCode,
			RawBody:    resp.String(),
		}
		var mapResp map[string]interface{}

		if err := json.Unmarshal(resp.Body, &mapResp); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrParsingJSON, err)
		}

		// Extract standard OAuth2 error fields if present
		if errStr, ok := mapResp["error"].(string); ok {
			oauth2Err.ErrorType = errStr
			if desc, ok := mapResp["error_description"].(string); ok {
				oauth2Err.ErrorDescription = desc
			}
			return nil, fmt.Errorf("%w: %v", ErrOAuthError, oauth2Err)
		}

		return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, oauth2Err)
	}

	var deviceAuthResp DeviceAuthorizationResponse
	if err := json.Unmarshal(resp.Body, &deviceAuthResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParsingJSON, err)
	}
	return &deviceAuthResp, nil
}
