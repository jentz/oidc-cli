//go:build acceptance

package acceptance

import (
	"net/http"
	"testing"
)

const expectedRefreshToken = "acceptance-refresh-token"

func newTokenRefreshProvider(t *testing.T) *tokenProvider {
	t.Helper()

	return newTokenProvider(t, tokenEndpointBehavior{
		valid: func(request tokenRequest) bool {
			return request.GrantType == "refresh_token" &&
				request.ClientID == expectedClientID &&
				request.ClientSecret == expectedClientSecret &&
				request.RefreshToken == expectedRefreshToken
		},
		errorStatus: http.StatusBadRequest,
		errorBody: map[string]any{
			"error":             "invalid_grant",
			"error_description": "refresh token was not accepted",
		},
		successBody: func(request tokenRequest) map[string]any {
			return map[string]any{
				"access_token":  "refreshed-access-token",
				"refresh_token": "rotated-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         request.Scope,
			}
		},
	})
}

func TestTokenRefreshSuccess(t *testing.T) {
	provider := newTokenRefreshProvider(t)

	result := Run(t,
		"token_refresh",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--refresh-token", expectedRefreshToken,
		"--scope", "openid profile",
	)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}

	token := result.JSON(t)

	assertEqual(t, token["access_token"], "refreshed-access-token", "access_token")
	assertEqual(t, token["refresh_token"], "rotated-refresh-token", "refresh_token")
	assertEqual(t, token["token_type"], "Bearer", "token_type")
	assertEqual(t, token["expires_in"], float64(3600), "expires_in")
	assertEqual(t, token["scope"], "openid profile", "scope")

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
	assertEqual(t, requests[0].RefreshToken, expectedRefreshToken, "refresh_token")
	assertEqual(t, requests[0].Scope, "openid profile", "scope")
}

func TestTokenRefreshTokenError(t *testing.T) {
	provider := newTokenRefreshProvider(t)
	wrongRefreshToken := "wrong-refresh-token"

	result := Run(t,
		"token_refresh",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--refresh-token", wrongRefreshToken,
	)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "authorization server rejected token request", "stderr")
	assertContains(t, result.Stderr, "invalid_grant", "stderr")
	assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
	assertNotContains(t, result.Stderr, wrongRefreshToken, "stderr")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].GrantType, "refresh_token", "grant_type")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].RefreshToken, wrongRefreshToken, "refresh_token")
}
