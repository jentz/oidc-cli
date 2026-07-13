//go:build acceptance

package acceptance

import (
	"net/http"
	"testing"
)

const sensitiveErrorRefreshToken = "sensitive-error-refresh-token"

func TestTokenEndpointFailureMessages(t *testing.T) {
	tests := []struct {
		name            string
		response        func(http.ResponseWriter)
		expectedStderr  []string
		unexpectedLeaks []string
	}{
		{
			name: "invalid JSON",
			response: func(w http.ResponseWriter) {
				writeText(w, http.StatusOK, "{not-json")
			},
			expectedStderr: []string{
				"invalid JSON response in token",
				"json parsing error",
			},
			unexpectedLeaks: []string{expectedClientSecret, sensitiveErrorRefreshToken},
		},
		{
			name: "non-OAuth HTTP failure",
			response: func(w http.ResponseWriter) {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"message": "provider unavailable",
				})
			},
			expectedStderr: []string{
				"HTTP request failed in token",
				"request failed with status: 500",
				"provider unavailable",
			},
			unexpectedLeaks: []string{expectedClientSecret, sensitiveErrorRefreshToken},
		},
		{
			name: "OAuth error with description",
			response: func(w http.ResponseWriter) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":             "invalid_grant",
					"error_description": "refresh token expired",
				})
			},
			expectedStderr: []string{
				"authorization server rejected token request",
				"invalid_grant",
				"refresh token expired",
			},
			unexpectedLeaks: []string{expectedClientSecret, sensitiveErrorRefreshToken},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newTokenEndpointErrorProvider(t, tt.response)

			result := Run(t,
				"token_refresh",
				"--issuer", provider.issuer(),
				"--client-id", expectedClientID,
				"--client-secret", expectedClientSecret,
				"--auth-method", "client_secret_post",
				"--refresh-token", sensitiveErrorRefreshToken,
				"--scope", "openid profile",
			)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
			}
			assertEqual(t, result.Stdout, "", "stdout")
			for _, want := range tt.expectedStderr {
				assertContains(t, result.Stderr, want, "stderr")
			}
			for _, leak := range tt.unexpectedLeaks {
				assertNotContains(t, result.Stdout, leak, "stdout")
				assertNotContains(t, result.Stderr, leak, "stderr")
			}

			discoveryRequests, requests := provider.requests()
			assertEqual(t, discoveryRequests, 1, "discovery request count")
			if len(requests) != 1 {
				t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
			}
			assertEqual(t, requests[0].Method, http.MethodPost, "token request method")
			assertEqual(t, requests[0].Authorization, "", "authorization header")
			assertEqual(t, requests[0].GrantType, "refresh_token", "grant_type")
			assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
			assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
			assertEqual(t, requests[0].RefreshToken, sensitiveErrorRefreshToken, "refresh_token")
			assertEqual(t, requests[0].Scope, "openid profile", "scope")
		})
	}
}

func newTokenEndpointErrorProvider(t *testing.T, response func(http.ResponseWriter)) *tokenProvider {
	t.Helper()

	return newTokenProvider(t, tokenEndpointBehavior{
		tokenResponse: func(w http.ResponseWriter, _ tokenRequest) {
			response(w)
		},
	})
}
