package httpclient

import (
	"strings"
	"testing"
)

func TestDefaultAuthorizationURLBuilder_BuildAuthorizationURL(t *testing.T) {
	builder := &DefaultAuthorizationURLBuilder{}

	tests := []struct {
		name        string
		endpoint    string
		req         *AuthorizationCodeRequest
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid request",
			endpoint: "https://example.com/auth",
			req: &AuthorizationCodeRequest{
				ClientID:    "test-client",
				RedirectURI: "http://localhost:8080/callback",
				Scope:       "openid profile",
				State:       "test-state",
			},
			want:    "https://example.com/auth?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&scope=openid+profile&state=test-state",
			wantErr: false,
		},
		{
			name:        "empty endpoint",
			endpoint:    "",
			req:         &AuthorizationCodeRequest{ClientID: "test-client"},
			wantErr:     true,
			errContains: "endpoint is required",
		},
		{
			name:        "nil request",
			endpoint:    "https://example.com/auth",
			req:         nil,
			wantErr:     true,
			errContains: "request cannot be nil",
		},
		{
			name:        "empty client ID",
			endpoint:    "https://example.com/auth",
			req:         &AuthorizationCodeRequest{},
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name:     "with PKCE parameters",
			endpoint: "https://example.com/auth",
			req: &AuthorizationCodeRequest{
				ClientID:            "test-client",
				CodeChallenge:       "test-challenge",
				CodeChallengeMethod: "S256",
			},
			want:    "https://example.com/auth?client_id=test-client&code_challenge=test-challenge&code_challenge_method=S256&response_type=code",
			wantErr: false,
		},
		{
			name:     "with custom args",
			endpoint: "https://example.com/auth",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				CustomArgs: &CustomArgs{
					"custom_param": "custom_value",
					"another":      "value",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := builder.BuildAuthorizationURL(tt.endpoint, tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildAuthorizationURL() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("BuildAuthorizationURL() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildAuthorizationURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want != "" && got != tt.want {
				t.Errorf("BuildAuthorizationURL() = %v, want %v", got, tt.want)
			}

			// For custom args test, just verify it doesn't error and contains expected parts
			if tt.req != nil && tt.req.CustomArgs != nil {
				if !strings.Contains(got, "custom_param=custom_value") {
					t.Errorf("BuildAuthorizationURL() = %v, should contain custom_param=custom_value", got)
				}
				if !strings.Contains(got, "another=value") {
					t.Errorf("BuildAuthorizationURL() = %v, should contain another=value", got)
				}
			}
		})
	}
}

func TestDefaultAuthorizationURLBuilder_Interface(_ *testing.T) {
	var _ AuthorizationURLBuilder = (*DefaultAuthorizationURLBuilder)(nil)
}
