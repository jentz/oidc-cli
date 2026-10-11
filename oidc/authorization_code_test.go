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
	"github.com/jentz/oidc-cli/httpclient"
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
		for attempt := 0; attempt < 120; attempt++ {
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

func TestAuthorizationCodeFlowRunNoBrowserPrintsAuthorizationURL(t *testing.T) {
	t.Parallel()

	const (
		callbackURI = "http://localhost/callback"
		authCode    = "manual-auth-code"
		state       = "manual-state"
		nonce       = "manual-nonce"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callbackErr := fireCallbackAsync(callbackTarget)

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			CallbackURI: callbackURI,
			State:       state,
			Nonce:       nonce,
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
	wantAuthorizationURL := "https://op.example.com/authorize?client_id=test-client&nonce=manual-nonce&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&state=manual-state"
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
		nonce       = "recovery-nonce"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	callbackErr := fireCallbackAsync(callbackTarget)

	flow := &AuthorizationCodeFlow{
		Config: fixture.config,
		FlowConfig: &AuthorizationCodeFlowConfig{
			CallbackURI: callbackURI,
			State:       state,
			Nonce:       nonce,
		},
	}
	if err := flow.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := <-callbackErr; err != nil {
		t.Fatalf("firing callback: %v", err)
	}

	wantAuthorizationURL := "https://op.example.com/authorize?client_id=test-client&nonce=recovery-nonce&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&state=recovery-state"
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

// TestAuthorizationCodeFlowRunPublicClient pins the PKCE no-secret fallback:
// with no client secret, the flow's PKCE setup must switch to no client
// authentication, so the token request carries client_id in the body and no
// Authorization header (and never an empty-secret Basic header).
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

// interactiveRun records what a single interactive Run put on the wire and
// wrote to stdout.
type interactiveRun struct {
	authQuery url.Values // query of the opened authorization URL
	parForm   url.Values // PAR body, when PAR is enabled
	output    string
	err       error
}

// runInteractive drives Run once with the given flow configuration. The fake
// browser echoes the state from the opened authorization URL back to the
// callback, unless callbackState overrides what the redirect carries.
// tokenBody builds the token response from the opened authorization URL's
// query; nil gives a response without an ID Token.
func runInteractive(t *testing.T, flowConf *AuthorizationCodeFlowConfig, callbackState func(sent string) string, tokenBody func(authQuery url.Values) string) interactiveRun {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding loopback listener: %v", err)
	}

	browser := &callbackFiringBrowser{}
	browser.fire = func() error {
		opened, err := url.Parse(browser.openedURL)
		if err != nil {
			return err
		}
		returned := opened.Query().Get("state")
		if callbackState != nil {
			returned = callbackState(returned)
		}
		callbackTarget := fmt.Sprintf("http://%s/callback?code=%s&state=%s",
			ln.Addr().String(), url.QueryEscape("auth-code"), url.QueryEscape(returned))
		resp, err := http.Get(callbackTarget) //nolint:noctx // test-local loopback request
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	openedQuery := func() url.Values {
		opened, err := url.Parse(browser.openedURL)
		if err != nil {
			return nil
		}
		return opened.Query()
	}

	opts := []fixtureOption{
		withBrowser(browser),
		withListener(func(_, _ string) (net.Listener, error) { return ln, nil }),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	}
	if tokenBody != nil {
		// The browser opens the authorization URL on the flow's goroutine
		// before the token request, so the opened URL is set by now.
		opts = append(opts, withRouteFunc(testTokenEndpoint, func() cannedResponse {
			return cannedResponse{status: http.StatusOK, body: tokenBody(openedQuery())}
		}))
	}
	if flowConf.PAR {
		opts = append(opts, withRoute(testPAREndpoint, http.StatusCreated,
			`{"request_uri":"urn:par:request-uri-456","expires_in":60}`))
	}
	fixture := newReadyConfig(t, opts...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flowConf.CallbackURI = "http://localhost/callback"
	flow := &AuthorizationCodeFlow{Config: fixture.config, FlowConfig: flowConf}

	run := interactiveRun{err: flow.Run(ctx)}
	run.authQuery = openedQuery()
	if flowConf.PAR && len(fixture.requests) > 0 {
		run.parForm = fixture.requests[0].Form
	}
	run.output = fixture.output.String()
	return run
}

// TestAuthorizationCodeFlowRunStateSource proves which state the flow sends
// and checks: --custom state wins over --state, which wins over a value
// generated per run. The same value reaches the authorization URL, the PAR
// body, and the callback check.
func TestAuthorizationCodeFlowRunStateSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      string
		customArgs *httpclient.CustomArgs
		want       string // empty means a generated value is expected
	}{
		{name: "generated by default"},
		{name: "--state is sent unchanged", state: "user-state", want: "user-state"},
		{
			name:       "--custom state wins over --state",
			state:      "user-state",
			customArgs: &httpclient.CustomArgs{"state": "custom-state"},
			want:       "custom-state",
		},
	}

	for _, tt := range tests {
		for _, par := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s par=%t", tt.name, par), func(t *testing.T) {
				t.Parallel()

				flowConf := &AuthorizationCodeFlowConfig{State: tt.state, CustomArgs: tt.customArgs, PAR: par}
				run := runInteractive(t, flowConf, nil, nil)
				if run.err != nil {
					t.Fatalf("Run() error = %v", run.err)
				}

				sent := run.authQuery.Get("state")
				if tt.want != "" {
					if sent != tt.want {
						t.Errorf("authorization state = %q, want %q", sent, tt.want)
					}
				} else if len(sent) < 8 {
					t.Errorf("authorization state = %q, want a generated value of at least 8 characters", sent)
				}
				if par && (!run.parForm.Has("state") || run.parForm.Get("state") != sent) {
					t.Errorf("PAR state = %q (present %t), want %q", run.parForm.Get("state"), run.parForm.Has("state"), sent)
				}
				// The generated value lives only in the run; the user's
				// configuration is not written back.
				if flowConf.State != tt.state {
					t.Errorf("FlowConfig.State = %q, want it unchanged at %q", flowConf.State, tt.state)
				}
			})
		}
	}

	t.Run("generated state differs between runs", func(t *testing.T) {
		t.Parallel()
		first := runInteractive(t, &AuthorizationCodeFlowConfig{}, nil, nil)
		second := runInteractive(t, &AuthorizationCodeFlowConfig{}, nil, nil)
		if first.err != nil || second.err != nil {
			t.Fatalf("Run() errors = %v, %v", first.err, second.err)
		}
		if first.authQuery.Get("state") == second.authQuery.Get("state") {
			t.Errorf("both runs sent state %q, want a new value per run", first.authQuery.Get("state"))
		}
	})

	t.Run("generated state is checked on the callback", func(t *testing.T) {
		t.Parallel()
		run := runInteractive(t, &AuthorizationCodeFlowConfig{}, func(string) string { return "attacker-state" }, nil)
		if run.err == nil || !strings.Contains(run.err.Error(), "state mismatch") {
			t.Errorf("Run() error = %v, want a state mismatch", run.err)
		}
	})

	t.Run("--custom state is checked on the callback", func(t *testing.T) {
		t.Parallel()
		flowConf := &AuthorizationCodeFlowConfig{
			State:      "user-state",
			CustomArgs: &httpclient.CustomArgs{"state": "custom-state"},
		}
		// A callback echoing the --state value instead of the sent custom
		// value must be rejected.
		run := runInteractive(t, flowConf, func(string) string { return "user-state" }, nil)
		if run.err == nil || !strings.Contains(run.err.Error(), "state mismatch") {
			t.Errorf("Run() error = %v, want a state mismatch", run.err)
		}
	})
}

// TestAuthorizationCodeFlowRunNonceSource proves which nonce the flow sends:
// --custom nonce wins over --nonce and --no-nonce; --no-nonce sends none;
// --nonce is sent unchanged; otherwise a value is generated per run. The same
// value reaches the authorization URL and the PAR body.
func TestAuthorizationCodeFlowRunNonceSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		nonce      string
		noNonce    bool
		customArgs *httpclient.CustomArgs
		wantSent   bool
		want       string // empty with wantSent means a generated value
	}{
		{name: "generated by default", wantSent: true},
		{name: "--nonce is sent unchanged", nonce: "user-nonce", wantSent: true, want: "user-nonce"},
		{name: "--no-nonce sends no nonce", noNonce: true},
		{
			name:       "--custom nonce wins over --nonce",
			nonce:      "user-nonce",
			customArgs: &httpclient.CustomArgs{"nonce": "custom-nonce"},
			wantSent:   true,
			want:       "custom-nonce",
		},
		{
			name:       "--custom nonce wins over --no-nonce",
			noNonce:    true,
			customArgs: &httpclient.CustomArgs{"nonce": "custom-nonce"},
			wantSent:   true,
			want:       "custom-nonce",
		},
		{
			name:       "empty --custom nonce is sent empty",
			customArgs: &httpclient.CustomArgs{"nonce": ""},
			wantSent:   true,
		},
	}

	for _, tt := range tests {
		for _, par := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s par=%t", tt.name, par), func(t *testing.T) {
				t.Parallel()

				flowConf := &AuthorizationCodeFlowConfig{
					Nonce: tt.nonce, NoNonce: tt.noNonce, CustomArgs: tt.customArgs, PAR: par,
				}
				run := runInteractive(t, flowConf, nil, nil)
				if run.err != nil {
					t.Fatalf("Run() error = %v", run.err)
				}

				sent := run.authQuery.Get("nonce")
				switch {
				case !tt.wantSent:
					if run.authQuery.Has("nonce") {
						t.Errorf("authorization nonce = %q, want no nonce parameter", sent)
					}
				case !run.authQuery.Has("nonce"):
					t.Errorf("authorization URL has no nonce parameter, want one")
				case tt.want != "":
					if sent != tt.want {
						t.Errorf("authorization nonce = %q, want %q", sent, tt.want)
					}
				case tt.customArgs != nil:
					if sent != "" {
						t.Errorf("authorization nonce = %q, want an empty value", sent)
					}
				case len(sent) != 43:
					t.Errorf("authorization nonce = %q, want a generated 43-character value", sent)
				}
				if par && (run.parForm.Has("nonce") != run.authQuery.Has("nonce") || run.parForm.Get("nonce") != sent) {
					t.Errorf("PAR nonce = %q (present %t), want %q (present %t)",
						run.parForm.Get("nonce"), run.parForm.Has("nonce"), sent, run.authQuery.Has("nonce"))
				}
				// The generated value lives only in the run; the user's
				// configuration is not written back.
				if flowConf.Nonce != tt.nonce {
					t.Errorf("FlowConfig.Nonce = %q, want it unchanged at %q", flowConf.Nonce, tt.nonce)
				}
			})
		}
	}

	t.Run("generated nonce differs between runs", func(t *testing.T) {
		t.Parallel()
		first := runInteractive(t, &AuthorizationCodeFlowConfig{}, nil, nil)
		second := runInteractive(t, &AuthorizationCodeFlowConfig{}, nil, nil)
		if first.err != nil || second.err != nil {
			t.Fatalf("Run() errors = %v, %v", first.err, second.err)
		}
		if first.authQuery.Get("nonce") == second.authQuery.Get("nonce") {
			t.Errorf("both runs sent nonce %q, want a new value per run", first.authQuery.Get("nonce"))
		}
	})
}

// unsignedIDToken returns a JWT-shaped ID Token with the given JSON payload.
// The flow checks the nonce claim without a signature check, so the header
// and signature only need the JWT shape.
func unsignedIDToken(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("signature"))
}

// tokenResponseWithIDToken returns a token response body carrying idToken.
func tokenResponseWithIDToken(idToken string) string {
	return fmt.Sprintf(`{"access_token":"abc123","token_type":"Bearer","id_token":%q}`, idToken)
}

// TestAuthorizationCodeFlowRunNonceCheck proves the nonce check on the ID
// Token: a matching claim succeeds; a forged, missing, or undecodable claim
// fails the run but still prints the token data, so the user sees the
// authorization server's real response.
func TestAuthorizationCodeFlowRunNonceCheck(t *testing.T) {
	t.Parallel()

	echoNonce := func(q url.Values) string {
		return tokenResponseWithIDToken(unsignedIDToken(fmt.Sprintf(`{"sub":"user","nonce":%q}`, q.Get("nonce"))))
	}
	fixed := func(body string) func(url.Values) string {
		return func(url.Values) string { return body }
	}
	forged := tokenResponseWithIDToken(unsignedIDToken(`{"sub":"user","nonce":"forged-nonce"}`))

	tests := []struct {
		name      string
		flowConf  *AuthorizationCodeFlowConfig
		tokenBody func(url.Values) string
		wantErr   string // empty means success
	}{
		{name: "matching generated nonce", flowConf: &AuthorizationCodeFlowConfig{}, tokenBody: echoNonce},
		{name: "matching --nonce", flowConf: &AuthorizationCodeFlowConfig{Nonce: "user-nonce"}, tokenBody: echoNonce},
		{name: "forged nonce", flowConf: &AuthorizationCodeFlowConfig{}, tokenBody: fixed(forged), wantErr: "nonce mismatch"},
		{
			name:      "missing nonce claim",
			flowConf:  &AuthorizationCodeFlowConfig{},
			tokenBody: fixed(tokenResponseWithIDToken(unsignedIDToken(`{"sub":"user"}`))),
			wantErr:   "nonce",
		},
		{
			name:      "ID Token without three parts",
			flowConf:  &AuthorizationCodeFlowConfig{},
			tokenBody: fixed(tokenResponseWithIDToken("not-a-jwt")),
			wantErr:   "id_token",
		},
		{
			name:      "ID Token payload is not JSON",
			flowConf:  &AuthorizationCodeFlowConfig{},
			tokenBody: fixed(tokenResponseWithIDToken("e30." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c2ln")),
			wantErr:   "id_token",
		},
		{
			name:      "ID Token payload is not base64url",
			flowConf:  &AuthorizationCodeFlowConfig{},
			tokenBody: fixed(tokenResponseWithIDToken("e30.!!!.c2ln")),
			wantErr:   "id_token",
		},
		{
			name:      "id_token is not a string",
			flowConf:  &AuthorizationCodeFlowConfig{},
			tokenBody: fixed(`{"access_token":"abc123","id_token":42}`),
			wantErr:   "id_token",
		},
		{
			// Only the JWT shape and the payload are read.
			name:     "unusual header and signature do not hide the nonce",
			flowConf: &AuthorizationCodeFlowConfig{},
			tokenBody: func(q url.Values) string {
				payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"nonce":%q}`, q.Get("nonce"))))
				return tokenResponseWithIDToken("not-json." + payload + ".not-base64!")
			},
		},
		{
			name:      "nonce claim is not a string",
			flowConf:  &AuthorizationCodeFlowConfig{Nonce: "123"},
			tokenBody: fixed(tokenResponseWithIDToken(unsignedIDToken(`{"nonce":123}`))),
			wantErr:   "nonce claim is not a string: got 123",
		},
		{name: "no ID Token", flowConf: &AuthorizationCodeFlowConfig{}, tokenBody: fixed(`{"access_token":"abc123","token_type":"Bearer"}`)},
		{name: "--no-nonce skips the check", flowConf: &AuthorizationCodeFlowConfig{NoNonce: true}, tokenBody: fixed(forged)},
		{
			name:      "empty --custom nonce skips the check",
			flowConf:  &AuthorizationCodeFlowConfig{CustomArgs: &httpclient.CustomArgs{"nonce": ""}},
			tokenBody: fixed(forged),
		},
		{
			// An ID Token echoing the --nonce value instead of the sent custom
			// value must be rejected.
			name: "--custom nonce is checked",
			flowConf: &AuthorizationCodeFlowConfig{
				Nonce:      "user-nonce",
				CustomArgs: &httpclient.CustomArgs{"nonce": "custom-nonce"},
			},
			tokenBody: fixed(tokenResponseWithIDToken(unsignedIDToken(`{"nonce":"user-nonce"}`))),
			wantErr:   "nonce mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			run := runInteractive(t, tt.flowConf, nil, tt.tokenBody)
			if tt.wantErr == "" {
				if run.err != nil {
					t.Fatalf("Run() error = %v, want success", run.err)
				}
			} else if run.err == nil || !strings.Contains(run.err.Error(), tt.wantErr) {
				t.Fatalf("Run() error = %v, want an error containing %q", run.err, tt.wantErr)
			}
			// The token data is printed whether or not the check passes.
			if !strings.Contains(run.output, `"access_token": "abc123"`) {
				t.Errorf("stdout = %q, want the token data", run.output)
			}
		})
	}

	t.Run("mismatch names both values", func(t *testing.T) {
		t.Parallel()
		run := runInteractive(t, &AuthorizationCodeFlowConfig{Nonce: "user-nonce"}, nil, fixed(forged))
		want := `nonce mismatch: expected "user-nonce" but got "forged-nonce"`
		if run.err == nil || !strings.Contains(run.err.Error(), want) {
			t.Errorf("Run() error = %v, want it to contain %q", run.err, want)
		}
	})
}
