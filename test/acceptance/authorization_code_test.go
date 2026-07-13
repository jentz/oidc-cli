//go:build acceptance

package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	expectedAuthorizationCode  = "acceptance-auth-code"
	expectedAuthorizationState = "acceptance-state"
)

type authorizationRequest struct {
	Method              string
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallengeMethod string
	CodeChallenge       string
}

type authorizationProvider struct {
	server *httptest.Server

	redirectError bool

	mu                    sync.Mutex
	discoveryRequests     int
	authorizationRequests []authorizationRequest
	tokenRequests         []tokenRequest
}

func newAuthorizationProvider(t *testing.T, redirectError bool) *authorizationProvider {
	t.Helper()

	provider := &authorizationProvider{redirectError: redirectError}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/authorize", provider.handleAuthorization)
	mux.HandleFunc("/token", provider.handleToken)

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *authorizationProvider) issuer() string {
	return p.server.URL
}

func (p *authorizationProvider) requests() (int, []authorizationRequest, []tokenRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	authorizationRequests := make([]authorizationRequest, len(p.authorizationRequests))
	copy(authorizationRequests, p.authorizationRequests)
	tokenRequests := make([]tokenRequest, len(p.tokenRequests))
	copy(tokenRequests, p.tokenRequests)

	return p.discoveryRequests, authorizationRequests, tokenRequests
}

func (p *authorizationProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	p.discoveryRequests++
	p.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 p.server.URL,
		"authorization_endpoint": p.server.URL + "/authorize",
		"token_endpoint":         p.server.URL + "/token",
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post",
		},
	})
}

func (p *authorizationProvider) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	request := authorizationRequest{
		Method:              r.Method,
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		CodeChallenge:       query.Get("code_challenge"),
	}

	p.mu.Lock()
	p.authorizationRequests = append(p.authorizationRequests, request)
	p.mu.Unlock()

	redirectURL, err := url.Parse(request.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	redirectQuery := redirectURL.Query()
	redirectQuery.Set("state", request.State)
	if p.redirectError {
		redirectQuery.Set("error", "access_denied")
		redirectQuery.Set("error_description", "user denied authorization")
	} else {
		redirectQuery.Set("code", expectedAuthorizationCode)
	}
	redirectURL.RawQuery = redirectQuery.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (p *authorizationProvider) handleToken(w http.ResponseWriter, r *http.Request) {
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
		Code:          r.PostForm.Get("code"),
		RedirectURI:   r.PostForm.Get("redirect_uri"),
		CodeVerifier:  r.PostForm.Get("code_verifier"),
	}

	p.mu.Lock()
	p.tokenRequests = append(p.tokenRequests, request)
	p.mu.Unlock()

	if request.GrantType != "authorization_code" || request.Code != expectedAuthorizationCode || request.ClientID != expectedClientID || request.ClientSecret != expectedClientSecret {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "authorization code was not accepted",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  "acceptance-authorization-code-token",
		"refresh_token": "acceptance-authorization-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid profile",
	})
}

func TestAuthorizationCodeFlowSuccess(t *testing.T) {
	provider := newAuthorizationProvider(t, false)
	callbackURI := reserveLoopbackCallbackURI(t)

	result := runAuthorizationCodeFlow(t, provider, callbackURI)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}
	assertContains(t, result.Stderr, "Open this URL in a browser to authorize:\n"+provider.issuer()+"/authorize?", "stderr")

	assertNotContains(t, result.Stdout, expectedAuthorizationCode, "stdout")
	token := result.JSON(t)
	assertEqual(t, token["access_token"], "acceptance-authorization-code-token", "access_token")
	assertEqual(t, token["refresh_token"], "acceptance-authorization-refresh-token", "refresh_token")
	assertEqual(t, token["token_type"], "Bearer", "token_type")
	assertEqual(t, token["expires_in"], float64(3600), "expires_in")
	assertEqual(t, token["scope"], "openid profile", "scope")

	assertAuthorizationCodeRequests(t, provider, callbackURI, true)
}

func TestAuthorizationCodeFlowCallbackError(t *testing.T) {
	provider := newAuthorizationProvider(t, true)
	callbackURI := reserveLoopbackCallbackURI(t)

	result := runAuthorizationCodeFlow(t, provider, callbackURI)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "authorization request failed", "stderr")
	assertContains(t, result.Stderr, "access_denied", "stderr")
	assertContains(t, result.Stderr, "user denied authorization", "stderr")
	assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
	assertNotContains(t, result.Stdout, expectedClientSecret, "stdout")

	assertAuthorizationCodeRequests(t, provider, callbackURI, false)
}

func runAuthorizationCodeFlow(t *testing.T, provider *authorizationProvider, callbackURI string) Result {
	t.Helper()

	return runAndFollowAuthorizationURL(t,
		"--no-browser",
		"authorization_code",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--callback-uri", callbackURI,
		"--scope", "openid profile",
		"--state", expectedAuthorizationState,
		"--pkce",
	)
}

func assertAuthorizationCodeRequests(t *testing.T, provider *authorizationProvider, callbackURI string, expectTokenRequest bool) {
	t.Helper()

	discoveryRequests, authorizationRequests, tokenRequests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(authorizationRequests) != 1 {
		t.Fatalf("expected 1 authorization request, got %d: %#v", len(authorizationRequests), authorizationRequests)
	}
	authRequest := authorizationRequests[0]
	assertEqual(t, authRequest.Method, http.MethodGet, "authorization request method")
	assertEqual(t, authRequest.ResponseType, "code", "authorization response_type")
	assertEqual(t, authRequest.ClientID, expectedClientID, "authorization client_id")
	assertEqual(t, authRequest.RedirectURI, callbackURI, "authorization redirect_uri")
	assertEqual(t, authRequest.Scope, "openid profile", "authorization scope")
	assertEqual(t, authRequest.State, expectedAuthorizationState, "authorization state")
	assertEqual(t, authRequest.CodeChallengeMethod, "S256", "authorization code_challenge_method")

	if expectTokenRequest {
		if len(tokenRequests) != 1 {
			t.Fatalf("expected 1 token request, got %d: %#v", len(tokenRequests), tokenRequests)
		}
		tokenRequest := tokenRequests[0]
		assertEqual(t, tokenRequest.Method, http.MethodPost, "token request method")
		assertEqual(t, tokenRequest.Authorization, "", "authorization header")
		assertEqual(t, tokenRequest.GrantType, "authorization_code", "grant_type")
		assertEqual(t, tokenRequest.ClientID, expectedClientID, "token client_id")
		assertEqual(t, tokenRequest.ClientSecret, expectedClientSecret, "token client_secret")
		assertEqual(t, tokenRequest.Code, expectedAuthorizationCode, "authorization code")
		assertEqual(t, tokenRequest.RedirectURI, callbackURI, "token redirect_uri")
		assertEqual(t, authRequest.CodeChallenge, pkceS256Challenge(tokenRequest.CodeVerifier), "PKCE code challenge")
		return
	}

	if len(tokenRequests) != 0 {
		t.Fatalf("expected no token requests after callback error, got %d: %#v", len(tokenRequests), tokenRequests)
	}
}

func runAndFollowAuthorizationURL(t *testing.T, args ...string) Result {
	t.Helper()

	bin := RequireBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- acceptance tests intentionally execute the configured oidc-cli binary.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)
	authorizationURL := make(chan string, 1)

	go func() {
		_, err := io.Copy(&stdout, stdoutPipe)
		stdoutDone <- err
	}()
	go scanStderrForAuthorizationURL(stderrPipe, &stderr, authorizationURL, stderrDone)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start oidc-cli: %v", err)
	}

	select {
	case rawURL := <-authorizationURL:
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("create authorization request %q: %v", rawURL, err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("follow authorization URL %q: %v", rawURL, err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		if err := response.Body.Close(); err != nil {
			t.Fatalf("close authorization response: %v", err)
		}
	case <-ctx.Done():
		_ = cmd.Wait()
		<-stdoutDone
		<-stderrDone
		t.Fatalf("timed out waiting for authorization URL\nstderr:\n%s", stderr.String())
	}

	err = cmd.Wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Fatalf("oidc-cli command timed out or cancelled: %v", ctxErr)
	}
	if copyErr := <-stdoutDone; copyErr != nil {
		t.Fatalf("copy stdout: %v", copyErr)
	}
	if copyErr := <-stderrDone; copyErr != nil {
		t.Fatalf("copy stderr: %v", copyErr)
	}

	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result
		}
		t.Fatalf("failed to run oidc-cli: %v", err)
	}
	return result
}

func scanStderrForAuthorizationURL(r io.Reader, stderr *bytes.Buffer, authorizationURL chan<- string, done chan<- error) {
	scanner := bufio.NewScanner(r)
	sent := false
	for scanner.Scan() {
		line := scanner.Text()
		stderr.WriteString(line)
		stderr.WriteByte('\n')
		if !sent && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
			authorizationURL <- line
			sent = true
		}
	}
	done <- scanner.Err()
}

func reserveLoopbackCallbackURI(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve callback port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release callback port: %v", err)
	}
	return "http://" + addr + "/callback"
}

func pkceS256Challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
