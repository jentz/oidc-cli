package httpclient

import (
	"errors"
	"fmt"
)

// OAuth2 error types
var (
	ErrHTTPFailure          = errors.New("oauth http failure")
	ErrParsingJSON          = errors.New("json parsing error")
	ErrOAuthError           = errors.New("oauth protocol error")
	ErrIssuerInvalid        = errors.New("issuer does not match")
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("slow down")
)

// Error represents a standard OAuth2 error response
type Error struct {
	StatusCode       int
	ErrorType        string
	ErrorDescription string
	RawBody          string
}

func (e *Error) Error() string {
	if e.ErrorType != "" {
		if e.ErrorDescription != "" {
			return fmt.Sprintf("error: %s - %s, status: %d", e.ErrorType, e.ErrorDescription, e.StatusCode)
		}
		return fmt.Sprintf("error: %s, status: %d", e.ErrorType, e.StatusCode)
	}
	return fmt.Sprintf("request failed with status: %d, body: %s", e.StatusCode, e.RawBody)
}

func WrapError(err error, operation string) error {
	switch {
	case errors.Is(err, ErrParsingJSON):
		return fmt.Errorf("invalid JSON response in %s: %w", operation, err)
	case errors.Is(err, ErrOAuthError):
		return fmt.Errorf("authorization server rejected %s request: %w", operation, err)
	case errors.Is(err, ErrHTTPFailure):
		return fmt.Errorf("HTTP request failed in %s: %w", operation, err)
	case errors.Is(err, ErrAuthorizationPending):
		return fmt.Errorf("authorization pending during %s: %w", operation, err)
	case errors.Is(err, ErrSlowDown):
		return fmt.Errorf("slow down signal received during %s: %w", operation, err)
	default:
		return fmt.Errorf("%s error: %w", operation, err)
	}
}
