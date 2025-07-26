package httpclient

import (
	"errors"
	"fmt"
)

// DefaultAuthorizationURLBuilder implements AuthorizationURLBuilder using the existing logic.
type DefaultAuthorizationURLBuilder struct{}

// Ensure DefaultAuthorizationURLBuilder implements the interface.
var _ AuthorizationURLBuilder = (*DefaultAuthorizationURLBuilder)(nil)

// BuildAuthorizationURL creates a complete authorization URL from the endpoint and request parameters.
func (b *DefaultAuthorizationURLBuilder) BuildAuthorizationURL(endpoint string, req *AuthorizationCodeRequest) (string, error) {
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
