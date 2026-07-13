//go:build acceptance

package acceptance

import (
	"net/http"
	"testing"
)

func TestTokenRefreshAuthMethods(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		secretArgs []string
		valid      func(tokenRequest) bool
		assert     func(*testing.T, tokenRequest)
	}{
		{
			name:       "client_secret_basic",
			method:     "client_secret_basic",
			secretArgs: []string{"--client-secret", expectedClientSecret},
			valid: func(request tokenRequest) bool {
				return request.Authorization == expectedBasicAuthorization() &&
					request.ClientID == "" &&
					request.ClientSecret == "" &&
					request.RefreshToken == expectedRefreshToken
			},
			assert: func(t *testing.T, request tokenRequest) {
				t.Helper()
				assertEqual(t, request.Authorization, expectedBasicAuthorization(), "authorization header")
				assertEqual(t, request.ClientID, "", "client_id")
				assertEqual(t, request.ClientSecret, "", "client_secret")
			},
		},
		{
			name:       "client_secret_post",
			method:     "client_secret_post",
			secretArgs: []string{"--client-secret", expectedClientSecret},
			valid: func(request tokenRequest) bool {
				return request.Authorization == "" &&
					request.ClientID == expectedClientID &&
					request.ClientSecret == expectedClientSecret &&
					request.RefreshToken == expectedRefreshToken
			},
			assert: func(t *testing.T, request tokenRequest) {
				t.Helper()
				assertEqual(t, request.Authorization, "", "authorization header")
				assertEqual(t, request.ClientID, expectedClientID, "client_id")
				assertEqual(t, request.ClientSecret, expectedClientSecret, "client_secret")
			},
		},
		{
			name:       "none",
			method:     "none",
			secretArgs: nil,
			valid: func(request tokenRequest) bool {
				return request.Authorization == "" &&
					request.ClientID == expectedClientID &&
					request.ClientSecret == "" &&
					request.RefreshToken == expectedRefreshToken
			},
			assert: func(t *testing.T, request tokenRequest) {
				t.Helper()
				assertEqual(t, request.Authorization, "", "authorization header")
				assertEqual(t, request.ClientID, expectedClientID, "client_id")
				assertEqual(t, request.ClientSecret, "", "client_secret")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newAuthMethodProvider(t, tt.valid)
			args := []string{
				"token_refresh",
				"--issuer", provider.issuer(),
				"--client-id", expectedClientID,
				"--auth-method", tt.method,
				"--refresh-token", expectedRefreshToken,
			}
			args = append(args, tt.secretArgs...)

			result := Run(t, args...)

			if result.ExitCode != 0 {
				t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
			}
			token := result.JSON(t)
			assertEqual(t, token["access_token"], "auth-method-access-token", "access_token")
			assertEqual(t, token["token_type"], "Bearer", "token_type")
			assertEqual(t, token["expires_in"], float64(3600), "expires_in")

			discoveryRequests, requests := provider.requests()
			assertEqual(t, discoveryRequests, 1, "discovery request count")
			if len(requests) != 1 {
				t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
			}
			assertEqual(t, requests[0].Method, http.MethodPost, "token request method")
			assertEqual(t, requests[0].GrantType, "refresh_token", "grant_type")
			assertEqual(t, requests[0].RefreshToken, expectedRefreshToken, "refresh_token")
			tt.assert(t, requests[0])
		})
	}
}

func newAuthMethodProvider(t *testing.T, valid func(tokenRequest) bool) *tokenProvider {
	t.Helper()

	return newTokenProvider(t, tokenEndpointBehavior{
		valid:       valid,
		errorStatus: http.StatusUnauthorized,
		errorBody: map[string]any{
			"error":             "invalid_client",
			"error_description": "client authentication was not accepted",
		},
		successBody: func(tokenRequest) map[string]any {
			return map[string]any{
				"access_token": "auth-method-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
		},
	})
}

func expectedBasicAuthorization() string {
	// Basic encoding of "acceptance-client:acceptance-secret".
	return "Basic YWNjZXB0YW5jZS1jbGllbnQ6YWNjZXB0YW5jZS1zZWNyZXQ="
}
