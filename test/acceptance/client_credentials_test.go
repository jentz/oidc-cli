//go:build acceptance

package acceptance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	expectedClientID     = "acceptance-client"
	expectedClientSecret = "acceptance-secret"
)

type tokenRequest struct {
	Method        string
	Authorization string
	GrantType     string
	ClientID      string
	ClientSecret  string
	Scope         string
}

type acceptanceProvider struct {
	server *httptest.Server

	mu                sync.Mutex
	discoveryRequests int
	tokenRequests     []tokenRequest
}

func newAcceptanceProvider(t *testing.T) *acceptanceProvider {
	t.Helper()

	provider := &acceptanceProvider{}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		provider.mu.Lock()
		provider.discoveryRequests++
		provider.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                provider.server.URL,
			"token_endpoint":                        provider.server.URL + "/token",
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		request := tokenRequest{
			Method:        r.Method,
			Authorization: r.Header.Get("Authorization"),
			GrantType:     r.PostForm.Get("grant_type"),
			ClientID:      r.PostForm.Get("client_id"),
			ClientSecret:  r.PostForm.Get("client_secret"),
			Scope:         r.PostForm.Get("scope"),
		}

		provider.mu.Lock()
		provider.tokenRequests = append(provider.tokenRequests, request)
		provider.mu.Unlock()

		if request.GrantType != "client_credentials" || request.ClientID != expectedClientID || request.ClientSecret != expectedClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":             "invalid_client",
				"error_description": "client credentials were not accepted",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "acceptance-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        request.Scope,
		})
	})

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *acceptanceProvider) issuer() string {
	return p.server.URL
}

func (p *acceptanceProvider) requests() (int, []tokenRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	requests := make([]tokenRequest, len(p.tokenRequests))
	copy(requests, p.tokenRequests)
	return p.discoveryRequests, requests
}
func TestClientCredentialsSuccess(t *testing.T) {
	provider := newAcceptanceProvider(t)

	result := Run(t,
		"client_credentials",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--scope", "openid profile",
	)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}

	token := result.JSON(t)

	assertEqual(t, token["access_token"], "acceptance-access-token", "access_token")
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
	assertEqual(t, requests[0].GrantType, "client_credentials", "grant_type")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].Scope, "openid profile", "scope")
}

func TestClientCredentialsTokenError(t *testing.T) {
	provider := newAcceptanceProvider(t)

	result := Run(t,
		"client_credentials",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", "wrong-secret",
		"--auth-method", "client_secret_post",
	)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "authorization server rejected token request", "stderr")
	assertContains(t, result.Stderr, "invalid_client", "stderr")
	assertNotContains(t, result.Stderr, "wrong-secret", "stderr")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 token request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].GrantType, "client_credentials", "grant_type")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, "wrong-secret", "client_secret")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func assertEqual(t *testing.T, got, want any, name string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s: got %v, want %v", name, got, want)
	}
}

func assertContains(t *testing.T, got, want, name string) {
	t.Helper()

	if !strings.Contains(got, want) {
		t.Fatalf("%s: got %q, want it to contain %q", name, got, want)
	}
}

func assertNotContains(t *testing.T, got, unwanted, name string) {
	t.Helper()

	if strings.Contains(got, unwanted) {
		t.Fatalf("%s: got %q, want it not to contain %q", name, got, unwanted)
	}
}
