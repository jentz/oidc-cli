//go:build acceptance

package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	forgedAuthorizationState   = "forged-state"
	expectedAuthorizationNonce = "acceptance-nonce"
	forgedIDTokenNonce         = "forged-nonce"
)

type authorizationRequest struct {
	Method              string
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	HasNonce            bool
	CodeChallengeMethod string
	CodeChallenge       string
}

// callbackOutcome selects what the fake provider sends to the callback.
type callbackOutcome int

const (
	callbackCode callbackOutcome = iota
	callbackError
	// callbackErrorWithoutState models providers that omit state on an error
	// redirect.
	callbackErrorWithoutState
	// callbackCodeWithForgedState returns a code with a state the client never
	// sent, as a forged callback would.
	callbackCodeWithForgedState
)

type authorizationProvider struct {
	server *httptest.Server

	outcome callbackOutcome
	// forgeIDTokenNonce makes the token endpoint return an ID Token whose
	// nonce claim the client never sent, as a replayed ID Token would carry.
	forgeIDTokenNonce bool

	mu                    sync.Mutex
	discoveryRequests     int
	authorizationRequests []authorizationRequest
	tokenRequests         []tokenRequest
}

// providerOption configures the fake provider before it starts serving.
type providerOption func(*authorizationProvider)

func withForgedIDTokenNonce() providerOption {
	return func(p *authorizationProvider) { p.forgeIDTokenNonce = true }
}

func newAuthorizationProvider(t *testing.T, outcome callbackOutcome, opts ...providerOption) *authorizationProvider {
	t.Helper()

	provider := &authorizationProvider{outcome: outcome}
	for _, opt := range opts {
		opt(provider)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/authorize", provider.handleAuthorization)
	mux.HandleFunc("/token", provider.handleToken)

	// Start only after the field is set: handlers read provider.server.
	provider.server = httptest.NewUnstartedServer(mux)
	provider.server.Start()
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
		Nonce:               query.Get("nonce"),
		HasNonce:            query.Has("nonce"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		CodeChallenge:       query.Get("code_challenge"),
	}

	p.mu.Lock()
	p.authorizationRequests = append(p.authorizationRequests, request)
	p.mu.Unlock()

	if request.RedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	redirectURL, err := url.Parse(request.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	redirectQuery := redirectURL.Query()
	switch p.outcome {
	case callbackCode:
		redirectQuery.Set("state", request.State)
		redirectQuery.Set("code", expectedAuthorizationCode)
	case callbackCodeWithForgedState:
		redirectQuery.Set("state", forgedAuthorizationState)
		redirectQuery.Set("code", expectedAuthorizationCode)
	case callbackError:
		redirectQuery.Set("state", request.State)
		redirectQuery.Set("error", "access_denied")
		redirectQuery.Set("error_description", "user denied authorization")
	case callbackErrorWithoutState:
		redirectQuery.Set("error", "access_denied")
		redirectQuery.Set("error_description", "user denied authorization")
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
	var authRequest authorizationRequest
	if n := len(p.authorizationRequests); n > 0 {
		authRequest = p.authorizationRequests[n-1]
	}
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
		"id_token":      p.idToken(authRequest),
	})
}

// idToken returns an unsigned ID Token for the authorization request. Like a
// real provider, it echoes the request's nonce and omits the claim when the
// request had none.
func (p *authorizationProvider) idToken(authRequest authorizationRequest) string {
	claims := map[string]any{
		"iss": p.server.URL,
		"sub": "acceptance-user",
		"aud": expectedClientID,
	}
	switch {
	case p.forgeIDTokenNonce:
		claims["nonce"] = forgedIDTokenNonce
	case authRequest.HasNonce:
		claims["nonce"] = authRequest.Nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte("signature"))
}

// TestAuthorizationCodeFlowSuccess also covers --state: the given value is
// sent unchanged and checked on the callback.
func TestAuthorizationCodeFlowSuccess(t *testing.T) {
	provider := newAuthorizationProvider(t, callbackCode)
	callbackURI := reserveLoopbackCallbackURI(t)

	result := runAuthorizationCodeFlow(t, provider, callbackURI, "--state", expectedAuthorizationState)

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

	assertAuthorizationCodeRequests(t, provider, callbackURI, expectedAuthorizationState, true)
}

func TestAuthorizationCodeFlowGeneratedState(t *testing.T) {
	provider := newAuthorizationProvider(t, callbackCode)
	callbackURI := reserveLoopbackCallbackURI(t)

	result := runAuthorizationCodeFlow(t, provider, callbackURI)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}
	token := result.JSON(t)
	assertEqual(t, token["access_token"], "acceptance-authorization-code-token", "access_token")

	assertAuthorizationCodeRequests(t, provider, callbackURI, "", true)
}

func TestAuthorizationCodeFlowForgedState(t *testing.T) {
	provider := newAuthorizationProvider(t, callbackCodeWithForgedState)
	callbackURI := reserveLoopbackCallbackURI(t)

	result := runAuthorizationCodeFlow(t, provider, callbackURI)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertContains(t, result.Stderr, "state mismatch", "stderr")

	assertAuthorizationCodeRequests(t, provider, callbackURI, "", false)
}

func TestAuthorizationCodeFlowNonce(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantSent  bool
		wantNonce string // empty with wantSent means a generated value
	}{
		{name: "generated", wantSent: true},
		{name: "--nonce", args: []string{"--nonce", expectedAuthorizationNonce}, wantSent: true, wantNonce: expectedAuthorizationNonce},
		{name: "--no-nonce", args: []string{"--no-nonce"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newAuthorizationProvider(t, callbackCode)
			callbackURI := reserveLoopbackCallbackURI(t)

			result := runAuthorizationCodeFlow(t, provider, callbackURI, tt.args...)

			if result.ExitCode != 0 {
				t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
			}
			token := result.JSON(t)
			assertEqual(t, token["access_token"], "acceptance-authorization-code-token", "access_token")
			if _, ok := token["id_token"]; !ok {
				t.Errorf("stdout has no id_token: %s", result.Stdout)
			}

			_, authorizationRequests, _ := provider.requests()
			if len(authorizationRequests) != 1 {
				t.Fatalf("expected 1 authorization request, got %d", len(authorizationRequests))
			}
			authRequest := authorizationRequests[0]
			switch {
			case !tt.wantSent:
				if authRequest.HasNonce {
					t.Errorf("authorization nonce: got %q, want no nonce parameter", authRequest.Nonce)
				}
			case tt.wantNonce != "":
				assertEqual(t, authRequest.Nonce, tt.wantNonce, "authorization nonce")
			case len(authRequest.Nonce) < 8:
				t.Errorf("authorization nonce: got %q, want a generated value of at least 8 characters", authRequest.Nonce)
			}
		})
	}
}

// TestAuthorizationCodeFlowForgedNonce proves that the sent nonce is checked,
// whether generated or set with --nonce. A failed check still prints the token
// data, so the user sees the provider's real response, and the exit code
// reports the failure.
func TestAuthorizationCodeFlowForgedNonce(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "generated"},
		{name: "--nonce", args: []string{"--nonce", expectedAuthorizationNonce}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newAuthorizationProvider(t, callbackCode, withForgedIDTokenNonce())
			callbackURI := reserveLoopbackCallbackURI(t)

			result := runAuthorizationCodeFlow(t, provider, callbackURI, tt.args...)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
			}
			token := result.JSON(t)
			assertEqual(t, token["access_token"], "acceptance-authorization-code-token", "access_token")
			assertContains(t, result.Stderr, "nonce mismatch", "stderr")
			assertContains(t, result.Stderr, forgedIDTokenNonce, "stderr")
			assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")

			assertAuthorizationCodeRequests(t, provider, callbackURI, "", true)
		})
	}
}

func TestAuthorizationCodeFlowCallbackError(t *testing.T) {
	tests := []struct {
		name    string
		outcome callbackOutcome
	}{
		{name: "with state", outcome: callbackError},
		// The provider error must not be hidden behind a state mismatch.
		{name: "without state", outcome: callbackErrorWithoutState},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newAuthorizationProvider(t, tt.outcome)
			callbackURI := reserveLoopbackCallbackURI(t)

			result := runAuthorizationCodeFlow(t, provider, callbackURI, "--state", expectedAuthorizationState)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
			}
			assertEqual(t, result.Stdout, "", "stdout")
			assertContains(t, result.Stderr, "authorization request failed", "stderr")
			assertContains(t, result.Stderr, "access_denied", "stderr")
			assertContains(t, result.Stderr, "user denied authorization", "stderr")
			assertNotContains(t, result.Stderr, "state mismatch", "stderr")
			assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
			assertNotContains(t, result.Stdout, expectedClientSecret, "stdout")

			assertAuthorizationCodeRequests(t, provider, callbackURI, expectedAuthorizationState, false)
		})
	}
}

func runAuthorizationCodeFlow(t *testing.T, provider *authorizationProvider, callbackURI string, extraArgs ...string) Result {
	t.Helper()

	args := []string{
		"--no-browser",
		"authorization_code",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--callback-uri", callbackURI,
		"--scope", "openid profile",
		"--pkce",
	}
	return runAndFollowAuthorizationURL(t, append(args, extraArgs...)...)
}

// assertAuthorizationCodeRequests checks the requests the provider received.
// An empty wantState expects a generated state of at least 8 characters.
func assertAuthorizationCodeRequests(t *testing.T, provider *authorizationProvider, callbackURI, wantState string, expectTokenRequest bool) {
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
	if wantState == "" {
		if len(authRequest.State) < 8 {
			t.Errorf("authorization state: got %q, want a generated value of at least 8 characters", authRequest.State)
		}
	} else {
		assertEqual(t, authRequest.State, wantState, "authorization state")
	}
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

	// Give exec non-file writers rather than StdoutPipe/StderrPipe: exec then
	// copies the output itself and Wait returns only once every byte is
	// copied. With the *Pipe methods, Wait closes the read ends and races any
	// reader still draining them.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	stderrReader, stderrWriter := io.Pipe()
	cmd.Stderr = stderrWriter

	stderrDone := make(chan error, 1)
	authorizationURL := make(chan string, 1)
	go scanStderrForAuthorizationURL(stderrReader, &stderr, authorizationURL, stderrDone)

	if err := cmd.Start(); err != nil {
		_ = stderrWriter.Close()
		t.Fatalf("start oidc-cli: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		// All stderr is copied once Wait returns; end the scanner's input.
		_ = stderrWriter.Close()
		waitDone <- err
	}()

	var waitErr error
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
		waitErr = <-waitDone
	case waitErr = <-waitDone:
	case <-ctx.Done():
		waitErr = <-waitDone
	}

	if copyErr := <-stderrDone; copyErr != nil {
		t.Fatalf("copy stderr: %v", copyErr)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Fatalf("oidc-cli command timed out or cancelled: %v\nstderr:\n%s", ctxErr, stderr.String())
	}

	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result
		}
		t.Fatalf("failed to run oidc-cli: %v", waitErr)
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
