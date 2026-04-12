package httpclient

import (
	"errors"
	"testing"
)

func TestError_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{
			name: "full error with type and description",
			err: &Error{
				StatusCode:       400,
				ErrorType:        "invalid_request",
				ErrorDescription: "The request is missing a required parameter",
			},
			want: "error: invalid_request - The request is missing a required parameter, status: 400",
		},
		{
			name: "error with type only",
			err: &Error{
				StatusCode: 401,
				ErrorType:  "unauthorized",
			},
			want: "error: unauthorized, status: 401",
		},
		{
			name: "error without type",
			err: &Error{
				StatusCode: 500,
				RawBody:    "Internal Server Error",
			},
			want: "request failed with status: 500, body: Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		err       error
		operation string
		want      string
	}{
		{
			name:      "wrap ErrParsingJSON",
			err:       ErrParsingJSON,
			operation: "token request",
			want:      "invalid JSON response in token request: json parsing error",
		},
		{
			name:      "wrap ErrOAuthError",
			err:       ErrOAuthError,
			operation: "authorization",
			want:      "authorization server rejected authorization request: oauth protocol error",
		},
		{
			name:      "wrap ErrHTTPFailure",
			err:       ErrHTTPFailure,
			operation: "introspection",
			want:      "HTTP request failed in introspection: oauth http failure",
		},
		{
			name:      "wrap other error",
			err:       errors.New("unknown error"),
			operation: "test operation",
			want:      "test operation error: unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := WrapError(tt.err, tt.operation)
			if got.Error() != tt.want {
				t.Errorf("WrapError() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}
