package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jentz/oidc-cli/crypto/cryptotest"
)

// The authorization-code flow is exercised end-to-end through Run on stable
// seams: a pre-bound loopback listener stands in for the callback server's
// port, and a fake browser fires the redirect the flow is waiting for. The PAR
// and token calls ride the capture transport, so assertions stay on the wire
// (the authorization URL opened, the requests emitted, the bytes output) rather
// than on internal state.

// callbackFiringBrowser stands in for the system browser: it records the
// authorization URL it was asked to open, then drives the user's redirect by
// firing the callback GET the loopback server is waiting on. Open runs
// synchronously on the flow's goroutine and blocks until the server has
// answered, so the recorded URL is safe to read once Run returns.
type callbackFiringBrowser struct {
	openedURL string
	fire      func() error
}

func (b *callbackFiringBrowser) Open(rawURL string) error {
	b.openedURL = rawURL
	if b.fire != nil {
		return b.fire()
	}
	return nil
}

func fireCallbackAsync(callbackTarget string) <-chan error {
	callbackErr := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 20; attempt++ {
			resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
			if err == nil {
				callbackErr <- resp.Body.Close()
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		callbackErr <- fmt.Errorf("callback endpoint did not accept request at %s", callbackTarget)
	}()
	return callbackErr
}

func TestAuthorizationCodeFlowRun(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "auth-code-xyz"
		state       = "state-123"
	)

	tests := []struct {
		name string
		pkce bool
		par  bool
	}{
		{name: "plain", pkce: false, par: false},
		{name: "pkce", pkce: true, par: false},
		{name: "par", pkce: false, par: true},
		{name: "pkce and par", pkce: true, par: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Pre-bind a loopback listener so the redirect round-trips on an
			// OS-assigned port, independent of the callback URI's host.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("binding loopback listener: %v", err)
			}
			callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
				ln.Addr().String(), url.QueryEscape(authCode), url.QueryEscape(state))

			browser := &callbackFiringBrowser{
				fire: func() error {
					resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
					if err != nil {
						return err
					}
					return resp.Body.Close()
				},
			}

			opts := []fixtureOption{
				withBrowser(browser),
				withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
				withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
			}
			if tt.par {
				opts = append(opts, withRoute(testPAREndpoint, http.StatusCreated,
					`{"request_uri":"urn:par:request-uri-456","expires_in":60}`))
			}
			fixture := newReadyConfig(t, opts...)

			// A cancellable context lets the background callback server shut down
			// once Run returns, rather than leaking until the test binary exits.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			flow := &AuthorizationCodeFlow{
				Config: fixture.config,
				FlowConfig: &AuthorizationCodeFlowConfig{
					Scope:       "openid profile",
					CallbackURI: callbackURI,
					State:       state,
					PKCE:        tt.pkce,
					PAR:         tt.par,
				},
			}

			if err := flow.Run(ctx); err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			// The browser must be opened at the authorization endpoint carrying
			// the parameters the authorization server will read.
			authURL, err := url.Parse(browser.openedURL)
			if err != nil {
				t.Fatalf("parsing opened URL %q: %v", browser.openedURL, err)
			}
			if got := authURL.Scheme + "://" + authURL.Host + authURL.Path; got != testAuthorizationEndpoint {
				t.Errorf("authorization endpoint = %q, want %q", got, testAuthorizationEndpoint)
			}
			authQuery := authURL.Query()
			for key, want := range map[string]string{
				"response_type": "code",
				"client_id":     testClientID,
				"redirect_uri":  callbackURI,
				"state":         state,
				"scope":         "openid profile",
			} {
				if got := authQuery.Get(key); got != want {
					t.Errorf("authorization param %s = %q, want %q", key, got, want)
				}
			}
			if tt.pkce {
				if got := authQuery.Get("code_challenge_method"); got != "S256" {
					t.Errorf("code_challenge_method = %q, want S256", got)
				}
				// The challenge value itself is verified against the token
				// request's code_verifier below, proving the two are bound.
			} else if authQuery.Has("code_challenge") {
				t.Errorf("code_challenge = %q, want absent without PKCE", authQuery.Get("code_challenge"))
			}
			if tt.par && authQuery.Get("request_uri") != "urn:par:request-uri-456" {
				t.Errorf("request_uri = %q, want the PAR response value", authQuery.Get("request_uri"))
			}

			// The flow emits the PAR request (when enabled) then the token
			// exchange; the callback GET rides the loopback, not this transport.
			var tokenReq *capturedRequest
			if tt.par {
				if len(fixture.requests) != 2 {
					t.Fatalf("got %d emitted requests, want 2 (PAR + token)", len(fixture.requests))
				}
				parReq := fixture.requests[0]
				if parReq.URL != testPAREndpoint {
					t.Errorf("PAR url = %q, want %q", parReq.URL, testPAREndpoint)
				}
				if parReq.Method != http.MethodPost {
					t.Errorf("PAR method = %q, want POST", parReq.Method)
				}
				if got := parReq.Header.Get("Authorization"); got != basicAuthHeader() {
					t.Errorf("PAR Authorization = %q, want %q", got, basicAuthHeader())
				}
				if got := parReq.Form.Get("response_type"); got != "code" {
					t.Errorf("PAR response_type = %q, want code", got)
				}
				if got := parReq.Form.Get("client_id"); got != testClientID {
					t.Errorf("PAR client_id = %q, want %q", got, testClientID)
				}
				tokenReq = fixture.requests[1]
			} else {
				tokenReq = fixture.onlyRequest(t)
			}

			if tokenReq.URL != testTokenEndpoint {
				t.Errorf("token url = %q, want %q", tokenReq.URL, testTokenEndpoint)
			}
			if tokenReq.Method != http.MethodPost {
				t.Errorf("token method = %q, want POST", tokenReq.Method)
			}
			if got := tokenReq.Header.Get("Authorization"); got != basicAuthHeader() {
				t.Errorf("token Authorization = %q, want %q", got, basicAuthHeader())
			}
			if got := tokenReq.Form.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q, want authorization_code", got)
			}
			if got := tokenReq.Form.Get("code"); got != authCode {
				t.Errorf("code = %q, want %q", got, authCode)
			}
			if got := tokenReq.Form.Get("redirect_uri"); got != callbackURI {
				t.Errorf("redirect_uri = %q, want %q", got, callbackURI)
			}
			if tt.pkce {
				verifier := tokenReq.Form.Get("code_verifier")
				if verifier == "" {
					t.Error("code_verifier is empty, want the PKCE verifier on the token request")
				} else {
					// The authorization URL's challenge must be S256(verifier).
					// Asserting both are merely non-empty would pass even if the
					// challenge were unrelated to the verifier the AS receives.
					sum := sha256.Sum256([]byte(verifier))
					wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
					if got := authQuery.Get("code_challenge"); got != wantChallenge {
						t.Errorf("code_challenge = %q, want S256(code_verifier) = %q", got, wantChallenge)
					}
				}
			} else if tokenReq.Form.Has("code_verifier") {
				t.Errorf("code_verifier = %q, want absent without PKCE", tokenReq.Form.Get("code_verifier"))
			}

			wantOutput := `{
  "access_token": "abc123",
  "token_type": "Bearer"
}
`
			if got := fixture.output.String(); got != wantOutput {
				t.Errorf("output = %q, want %q", got, wantOutput)
			}
		})
	}
}

// TestAuthorizationCodeFlowRunPublicClient pins the PKCE no-secret fallback:
// with no client secret, the flow's PKCE setup must switch to no client
// authentication, so the token request carries client_id in the body and no
// Authorization header (and never an empty-secret Basic header).
func TestAuthorizationCodeFlowRunNoBrowserPrintsAuthorizationURL(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "manual-auth-code"
		state       = "manual-state"
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}
	callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
		ln.Addr().String(), url.QueryEscape(authCode), url.QueryEscape(state))

	browser := &recordingBrowser{}
	fixture := newReadyConfig(t,
		withNoBrowser(),
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callbackErr := fireCallbackAsync(callbackTarget)

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			CallbackURI: callbackURI,
			State:       state,
		},
	}
	if err := flow.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := <-callbackErr; err != nil {
		t.Fatalf("firing callback: %v", err)
	}

	if browser.openedURL != "" {
		t.Errorf("opened URL = %q, want no browser launch", browser.openedURL)
	}
	wantAuthorizationURL := "https://op.example.com/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&state=manual-state"
	wantErr := "Open this URL in a browser to authorize:\n" + wantAuthorizationURL + "\n"
	if got := fixture.errOutput.String(); got != wantErr {
		t.Errorf("stderr = %q, want %q", got, wantErr)
	}

	tokenReq := fixture.onlyRequest(t)
	if got := tokenReq.Form.Get("code"); got != authCode {
		t.Errorf("token code = %q, want %q", got, authCode)
	}
	wantOutput := `{
  "access_token": "abc123",
  "token_type": "Bearer"
}
`
	if got := fixture.output.String(); got != wantOutput {
		t.Errorf("stdout = %q, want final JSON only", got)
	}
}

func TestAuthorizationCodeFlowRunBrowserFailurePrintsRecoveryInstructions(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "recovery-auth-code"
		state       = "recovery-state"
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}
	callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
		ln.Addr().String(), url.QueryEscape(authCode), url.QueryEscape(state))

	browser := &failingBrowser{}
	fixture := newReadyConfig(t,
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callbackErr := fireCallbackAsync(callbackTarget)

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			CallbackURI: callbackURI,
			State:       state,
		},
	}
	if err := flow.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := <-callbackErr; err != nil {
		t.Fatalf("firing callback: %v", err)
	}

	wantAuthorizationURL := "https://op.example.com/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&state=recovery-state"
	if browser.openedURL != wantAuthorizationURL {
		t.Errorf("opened URL = %q, want %q", browser.openedURL, wantAuthorizationURL)
	}
	wantErr := "Unable to open browser automatically: browser command missing\nOpen this URL in a browser to authorize:\n" + wantAuthorizationURL + "\n"
	if got := fixture.errOutput.String(); got != wantErr {
		t.Errorf("stderr = %q, want %q", got, wantErr)
	}
	if got := fixture.onlyRequest(t).Form.Get("code"); got != authCode {
		t.Errorf("token code = %q, want %q", got, authCode)
	}
}

func TestAuthorizationCodeFlowRunPublicClient(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "auth-code-public"
		state       = "state-public"
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}
	callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
		ln.Addr().String(), url.QueryEscape(authCode), url.QueryEscape(state))

	browser := &callbackFiringBrowser{
		fire: func() error {
			resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	}

	fixture := newReadyConfig(t,
		withPublicClient(),
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			Scope:       "openid",
			CallbackURI: callbackURI,
			State:       state,
			PKCE:        true,
		},
	}

	if err := flow.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	tokenReq := fixture.onlyRequest(t)
	if got := tokenReq.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want no header for a public client", got)
	}
	if got := tokenReq.Form.Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q, want %q in the body", got, testClientID)
	}
	if tokenReq.Form.Has("client_secret") {
		t.Errorf("client_secret = %q, want absent for a public client", tokenReq.Form.Get("client_secret"))
	}
	if tokenReq.Form.Get("code_verifier") == "" {
		t.Error("code_verifier is empty, want the PKCE verifier on the token request")
	}
}

// TestAuthorizationCodeFlowRunDPoP verifies the token request carries a valid
// DPoP proof bound to the configured key, and that client authentication and
// the code survive on the DPoP path.
func TestAuthorizationCodeFlowRunDPoP(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "auth-code-dpop"
		state       = "state-dpop"
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}
	callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
		ln.Addr().String(), url.QueryEscape(authCode), url.QueryEscape(state))

	browser := &callbackFiringBrowser{
		fire: func() error {
			resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	}

	fixture := newReadyConfig(t,
		withDPoPKeys(),
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"DPoP"}`),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			Scope:       "openid",
			CallbackURI: callbackURI,
			State:       state,
			DPoP:        true,
		},
	}

	if err := flow.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	tokenReq := fixture.onlyRequest(t)
	if tokenReq.URL != testTokenEndpoint {
		t.Errorf("token url = %q, want %q", tokenReq.URL, testTokenEndpoint)
	}
	if got := tokenReq.Header.Get("Authorization"); got != basicAuthHeader() {
		t.Errorf("Authorization = %q, want %q", got, basicAuthHeader())
	}
	if got := tokenReq.Form.Get("code"); got != authCode {
		t.Errorf("code = %q, want %q", got, authCode)
	}

	// VerifyDPoPProof fails on an empty proof, so it doubles as the presence check.
	cryptotest.VerifyDPoPProof(t, tokenReq.Header.Get("DPoP"), fixture.dpopPublicKey, http.MethodPost, testTokenEndpoint)
}

// TestAuthorizationCodeFlowRunStateMismatch proves the CSRF check is wired into
// Run end-to-end: a callback whose state does not match the request is rejected
// before any token request is emitted. The isolated validateCallbackResponse
// test cannot prove that ExecuteAuthorizationCodeRequest actually consults it.
func TestAuthorizationCodeFlowRunStateMismatch(t *testing.T) {
	t.Parallel()

	const callbackURI = "http://localhost/callback"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}
	// The redirect carries a state the flow never issued, as a forged callback would.
	callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
		ln.Addr().String(), url.QueryEscape("auth-code"), url.QueryEscape("attacker-state"))

	browser := &callbackFiringBrowser{
		fire: func() error {
			resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	}

	fixture := newReadyConfig(t,
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			CallbackURI: callbackURI,
			State:       "expected-state",
		},
	}

	err = flow.Run(ctx)
	if err == nil {
		t.Fatal("Run() error = nil, want a state-mismatch error")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("error = %q, want it to mention a state mismatch", err)
	}
	// The flow must abort before exchanging the code, so no token request is sent.
	if len(fixture.requests) != 0 {
		t.Errorf("emitted %d requests, want 0 when the callback state is rejected", len(fixture.requests))
	}
}
