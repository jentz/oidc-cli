//go:build acceptance

package acceptance

import (
	"net/http"
	"testing"
)

const (
	expectedSubjectToken       = "acceptance-subject-token"
	expectedSubjectTokenType   = "urn:ietf:params:oauth:token-type:access_token"
	expectedRequestedTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
)

func newTokenExchangeProvider(t *testing.T) *tokenProvider {
	t.Helper()

	return newTokenProvider(t, tokenEndpointBehavior{
		valid: func(request tokenRequest) bool {
			return request.GrantType == "urn:ietf:params:oauth:grant-type:token-exchange" &&
				request.ClientID == expectedClientID &&
				request.ClientSecret == expectedClientSecret &&
				request.SubjectToken == expectedSubjectToken &&
				request.SubjectTokenType == expectedSubjectTokenType
		},
		errorStatus: http.StatusBadRequest,
		errorBody: map[string]any{
			"error":             "invalid_request",
			"error_description": "subject token was not accepted",
		},
		successBody: func(tokenRequest) map[string]any {
			return map[string]any{
				"access_token":      "exchanged-access-token",
				"issued_token_type": expectedRequestedTokenType,
				"token_type":        "Bearer",
				"expires_in":        3600,
				"scope":             "exchanged-scope",
			}
		},
	})
}

func TestTokenExchangeSuccess(t *testing.T) {
	provider := newTokenExchangeProvider(t)

	result := Run(t,
		"token_exchange",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--subject-token", expectedSubjectToken,
		"--subject-token-type", expectedSubjectTokenType,
		"--audience", "acceptance-api",
		"--resource", "https://api.example.test/resource",
		"--requested-token-type", expectedRequestedTokenType,
		"--scope", "openid profile",
	)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}

	token := result.JSON(t)

	assertEqual(t, token["access_token"], "exchanged-access-token", "access_token")
	assertEqual(t, token["issued_token_type"], expectedRequestedTokenType, "issued_token_type")
	assertEqual(t, token["token_type"], "Bearer", "token_type")
	assertEqual(t, token["expires_in"], float64(3600), "expires_in")
	assertEqual(t, token["scope"], "exchanged-scope", "scope")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Method, http.MethodPost, "token request method")
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].GrantType, "urn:ietf:params:oauth:grant-type:token-exchange", "grant_type")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].SubjectToken, expectedSubjectToken, "subject_token")
	assertEqual(t, requests[0].SubjectTokenType, expectedSubjectTokenType, "subject_token_type")
	assertEqual(t, requests[0].Audience, "acceptance-api", "audience")
	assertEqual(t, requests[0].Resource, "https://api.example.test/resource", "resource")
	assertEqual(t, requests[0].RequestedTokenType, expectedRequestedTokenType, "requested_token_type")
	assertEqual(t, requests[0].Scope, "openid profile", "scope")
}

func TestTokenExchangeTokenError(t *testing.T) {
	provider := newTokenExchangeProvider(t)
	wrongSubjectToken := "wrong-subject-token"

	result := Run(t,
		"token_exchange",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--subject-token", wrongSubjectToken,
		"--subject-token-type", expectedSubjectTokenType,
	)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "authorization server rejected token request", "stderr")
	assertContains(t, result.Stderr, "invalid_request", "stderr")
	assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
	assertNotContains(t, result.Stderr, wrongSubjectToken, "stderr")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].GrantType, "urn:ietf:params:oauth:grant-type:token-exchange", "grant_type")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].SubjectToken, wrongSubjectToken, "subject_token")
	assertEqual(t, requests[0].SubjectTokenType, expectedSubjectTokenType, "subject_token_type")
}
