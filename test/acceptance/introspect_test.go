//go:build acceptance

package acceptance

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

const (
	expectedIntrospectionToken = "acceptance-introspection-token"
	expectedTokenTypeHint      = "refresh_token"
	expectedAcceptHeader       = "application/token-introspection+jwt"
	expectedCustomAudience     = "acceptance-api"
)

type introspectionRequest struct {
	Method        string
	Authorization string
	Accept        string
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
	Audience      string
}

type introspectionProvider struct {
	server *httptest.Server

	mu                    sync.Mutex
	discoveryRequests     int
	introspectionRequests []introspectionRequest
}

func newIntrospectionProvider(t *testing.T) *introspectionProvider {
	t.Helper()

	provider := &introspectionProvider{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/introspect", provider.handleIntrospection)

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *introspectionProvider) issuer() string {
	return p.server.URL
}

func (p *introspectionProvider) requests() (int, []introspectionRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	requests := make([]introspectionRequest, len(p.introspectionRequests))
	copy(requests, p.introspectionRequests)
	return p.discoveryRequests, requests
}

func (p *introspectionProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	p.discoveryRequests++
	p.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 p.server.URL,
		"introspection_endpoint": p.server.URL + "/introspect",
	})
}

func (p *introspectionProvider) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	request := introspectionRequest{
		Method:        r.Method,
		Authorization: r.Header.Get("Authorization"),
		Accept:        r.Header.Get("Accept"),
		Token:         r.PostForm.Get("token"),
		TokenTypeHint: r.PostForm.Get("token_type_hint"),
		ClientID:      r.PostForm.Get("client_id"),
		ClientSecret:  r.PostForm.Get("client_secret"),
		Audience:      r.PostForm.Get("audience"),
	}

	p.mu.Lock()
	p.introspectionRequests = append(p.introspectionRequests, request)
	p.mu.Unlock()

	if request.Token != expectedIntrospectionToken ||
		request.TokenTypeHint != expectedTokenTypeHint ||
		request.ClientID != expectedClientID ||
		request.ClientSecret != expectedClientSecret ||
		request.Audience != expectedCustomAudience {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":             "invalid_token",
			"error_description": "introspection request was not accepted",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":    true,
		"client_id": expectedClientID,
		"scope":     "openid profile",
		"sub":       "subject-123",
		"exp":       1893456000,
	})
}

func TestIntrospectSuccess(t *testing.T) {
	provider := newIntrospectionProvider(t)

	result := Run(t,
		"introspect",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--token", expectedIntrospectionToken,
		"--token-type", expectedTokenTypeHint,
		"--accept-header", expectedAcceptHeader,
		"--custom", "audience="+expectedCustomAudience,
	)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}

	introspection := result.JSON(t)
	assertEqual(t, introspection["active"], true, "active")
	assertEqual(t, introspection["client_id"], expectedClientID, "client_id")
	assertEqual(t, introspection["scope"], "openid profile", "scope")
	assertEqual(t, introspection["sub"], "subject-123", "sub")
	assertEqual(t, introspection["exp"], float64(1893456000), "exp")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 introspection request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Method, http.MethodPost, "introspection request method")
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].Accept, expectedAcceptHeader, "accept header")
	assertEqual(t, requests[0].Token, expectedIntrospectionToken, "token")
	assertEqual(t, requests[0].TokenTypeHint, expectedTokenTypeHint, "token_type_hint")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].Audience, expectedCustomAudience, "audience")
}

func TestIntrospectProviderError(t *testing.T) {
	provider := newIntrospectionProvider(t)
	wrongToken := "wrong-introspection-token"

	result := Run(t,
		"introspect",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--token", wrongToken,
		"--token-type", expectedTokenTypeHint,
		"--accept-header", expectedAcceptHeader,
		"--custom", "audience="+expectedCustomAudience,
	)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "authorization server rejected introspection request", "stderr")
	assertContains(t, result.Stderr, "invalid_token", "stderr")
	assertContains(t, result.Stderr, "introspection request was not accepted", "stderr")
	assertNotContains(t, result.Stdout, expectedClientSecret, "stdout")
	assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
	assertNotContains(t, result.Stdout, wrongToken, "stdout")
	assertNotContains(t, result.Stderr, wrongToken, "stderr")

	discoveryRequests, requests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(requests) != 1 {
		t.Fatalf("expected 1 introspection request, got %d: %#v", len(requests), requests)
	}
	assertEqual(t, requests[0].Authorization, "", "authorization header")
	assertEqual(t, requests[0].Accept, expectedAcceptHeader, "accept header")
	assertEqual(t, requests[0].Token, wrongToken, "token")
	assertEqual(t, requests[0].TokenTypeHint, expectedTokenTypeHint, "token_type_hint")
	assertEqual(t, requests[0].ClientID, expectedClientID, "client_id")
	assertEqual(t, requests[0].ClientSecret, expectedClientSecret, "client_secret")
	assertEqual(t, requests[0].Audience, expectedCustomAudience, "audience")
}
