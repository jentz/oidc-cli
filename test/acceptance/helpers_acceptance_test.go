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
	Method             string
	Authorization      string
	GrantType          string
	ClientID           string
	ClientSecret       string
	DeviceCode         string
	RefreshToken       string
	Scope              string
	SubjectToken       string
	SubjectTokenType   string
	Audience           string
	Resource           string
	RequestedTokenType string
}

type tokenEndpointBehavior struct {
	valid func(tokenRequest) bool
	// tokenResponse fully owns the token endpoint response when set; the
	// valid/error/success fields are ignored.
	tokenResponse func(http.ResponseWriter, tokenRequest)
	errorStatus   int
	errorBody     map[string]any
	successBody   func(tokenRequest) map[string]any
}

type tokenProvider struct {
	server *httptest.Server

	behavior tokenEndpointBehavior

	mu                sync.Mutex
	discoveryRequests int
	tokenRequests     []tokenRequest
}

func newTokenProvider(t *testing.T, behavior tokenEndpointBehavior) *tokenProvider {
	t.Helper()

	provider := &tokenProvider{behavior: behavior}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/token", provider.handleToken)

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *tokenProvider) issuer() string {
	return p.server.URL
}

func (p *tokenProvider) requests() (int, []tokenRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	requests := make([]tokenRequest, len(p.tokenRequests))
	copy(requests, p.tokenRequests)
	return p.discoveryRequests, requests
}

func (p *tokenProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	p.discoveryRequests++
	p.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":         p.server.URL,
		"token_endpoint": p.server.URL + "/token",
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
	})
}

func (p *tokenProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	request := tokenRequest{
		Method:             r.Method,
		Authorization:      r.Header.Get("Authorization"),
		GrantType:          r.PostForm.Get("grant_type"),
		ClientID:           r.PostForm.Get("client_id"),
		ClientSecret:       r.PostForm.Get("client_secret"),
		DeviceCode:         r.PostForm.Get("device_code"),
		RefreshToken:       r.PostForm.Get("refresh_token"),
		Scope:              r.PostForm.Get("scope"),
		SubjectToken:       r.PostForm.Get("subject_token"),
		SubjectTokenType:   r.PostForm.Get("subject_token_type"),
		Audience:           r.PostForm.Get("audience"),
		Resource:           r.PostForm.Get("resource"),
		RequestedTokenType: r.PostForm.Get("requested_token_type"),
	}

	p.mu.Lock()
	p.tokenRequests = append(p.tokenRequests, request)
	p.mu.Unlock()

	if p.behavior.tokenResponse != nil {
		p.behavior.tokenResponse(w, request)
		return
	}

	if !p.behavior.valid(request) {
		writeJSON(w, p.behavior.errorStatus, p.behavior.errorBody)
		return
	}

	writeJSON(w, http.StatusOK, p.behavior.successBody(request))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func assertEqual(t *testing.T, got, want any, name string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s: got %#v, want %#v", name, got, want)
	}
}

func assertContains(t *testing.T, got, want, name string) {
	t.Helper()

	if !strings.Contains(got, want) {
		t.Fatalf("%s: got %#v, want it to contain %#v", name, got, want)
	}
}

func assertNotContains(t *testing.T, got, unwanted, name string) {
	t.Helper()

	if strings.Contains(got, unwanted) {
		t.Fatalf("%s: got %#v, want it not to contain %#v", name, got, unwanted)
	}
}
