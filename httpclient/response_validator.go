package httpclient

import (
	"errors"
	"fmt"

	"github.com/jentz/oidc-cli/webflow"
)

// DefaultResponseValidator implements ResponseValidator using the existing validation logic.
type DefaultResponseValidator struct{}

// Ensure DefaultResponseValidator implements the interface.
var _ ResponseValidator = (*DefaultResponseValidator)(nil)

// ValidateResponse validates the callback response and returns the authorization code response.
func (v *DefaultResponseValidator) ValidateResponse(req *AuthorizationCodeRequest, resp *webflow.CallbackResponse) (*AuthorizationCodeResponse, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if resp == nil {
		return nil, errors.New("response cannot be nil")
	}

	// Validate state parameter to prevent CSRF attacks
	if req.State != "" && resp.State != req.State {
		return nil, fmt.Errorf("state mismatch: expected %q but got %q", req.State, resp.State)
	}

	// Check for authorization errors
	if resp.Code == "" {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", resp.ErrorMsg, resp.ErrorDescription)
	}

	// Build the successful response
	return &AuthorizationCodeResponse{
		Code: resp.Code,
		State: func() string {
			if req.State != "" {
				return req.State
			}
			return ""
		}(),
	}, nil
}
