package oidc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/webflow"
)

// Flows are exercised through their Run entry point against this harness.
// Tests assert only on what crosses the Run seam — the HTTP requests emitted
// (method, URL, headers, form body) and the bytes written to output — never on
// config internals or unexported helpers, so they survive config refactors.

const (
	testClientID              = "test-client"
	testClientSecret          = "test-secret"
	testAuthorizationEndpoint = "https://op.example.com/authorize"
	testPAREndpoint           = "https://op.example.com/par"
	testDeviceAuthEndpoint    = "https://op.example.com/device_authorization"
	testTokenEndpoint         = "https://op.example.com/token"
	testIntrospectionEndpoint = "https://op.example.com/introspect"
)

// capturedRequest records the parts of an emitted request that a resource
// server would see on the wire. The decoded Form is populated for the
// form-encoded bodies the flows send.
type capturedRequest struct {
	Method string
	URL    string
	Header http.Header
	Form   url.Values
}

// flowFixture bundles a ready Config with the request capture and output buffer
// that let a flow test assert on the Run seam alone. The requests slice needs
// no lock because a flow drives its endpoint requests sequentially on the
// calling goroutine; the interactive callback round-trip rides a real loopback
// listener that never touches this transport, so no append races it.
type flowFixture struct {
	config   *Config
	requests []*capturedRequest
	output   *bytes.Buffer

	// dpopPublicKey is the key the fixture's DPoP proofs are bound to, set only
	// when withDPoPKeys is used, so tests can verify the emitted proof.
	dpopPublicKey any
}

// cannedResponse is the status and body the transport replies with for a route.
type cannedResponse struct {
	status int
	body   string
}

type fixtureSettings struct {
	clientID       string
	clientSecret   string
	authMethod     httpclient.AuthMethod
	dpopKeys       bool
	responseStatus int
	responseBody   string
	// routes overrides the default response per request URL, letting an
	// interactive flow return a request_uri from the PAR endpoint and a token
	// from the token endpoint within one Run.
	routes  map[string]cannedResponse
	browser webflow.Browser
	listen  func(network, addr string) (net.Listener, error)
}

type fixtureOption func(*fixtureSettings)

// withRoute sets the canned response the transport returns for a specific
// request URL, overriding the default for that endpoint only.
func withRoute(url string, status int, body string) fixtureOption {
	return func(s *fixtureSettings) {
		if s.routes == nil {
			s.routes = make(map[string]cannedResponse)
		}
		s.routes[url] = cannedResponse{status: status, body: body}
	}
}

// withBrowser injects the browser the client opens authorization URLs through,
// letting an interactive-flow test fire the callback or no-op the launch.
func withBrowser(b webflow.Browser) fixtureOption {
	return func(s *fixtureSettings) { s.browser = b }
}

// withListener injects the function the callback server binds its listener
// with, letting a test drive the redirect over a pre-bound loopback port.
func withListener(fn func(network, addr string) (net.Listener, error)) fixtureOption {
	return func(s *fixtureSettings) { s.listen = fn }
}

// withAuthMethod overrides the client authentication method (default Basic).
func withAuthMethod(m httpclient.AuthMethod) fixtureOption {
	return func(s *fixtureSettings) { s.authMethod = m }
}

// withPublicClient models a public client: no secret, with the auth method
// left at Basic so a flow's PKCE setup is what flips it to None. It exercises
// the no-secret fallback that confidential-client cases never reach.
func withPublicClient() fixtureOption {
	return func(s *fixtureSettings) {
		s.clientSecret = ""
		s.authMethod = httpclient.AuthMethodBasic
	}
}

// withDPoPKeys loads a freshly generated ECDSA P-256 keypair into the config,
// modeling the post-key-load state; the public key is exposed on the fixture.
func withDPoPKeys() fixtureOption {
	return func(s *fixtureSettings) { s.dpopKeys = true }
}

// withResponse sets the canned response the transport returns for every request.
func withResponse(status int, body string) fixtureOption {
	return func(s *fixtureSettings) {
		s.responseStatus = status
		s.responseBody = body
	}
}

// newReadyConfig returns a fixture whose Config is in the state a flow sees
// after discovery and key loading have run: endpoints populated, credentials
// and auth method set, optional DPoP keys parsed. The Client is wired to a
// transport that records every request and replies with the canned response,
// and the Logger writes to an in-memory buffer.
func newReadyConfig(t *testing.T, opts ...fixtureOption) *flowFixture {
	t.Helper()

	settings := &fixtureSettings{
		clientID:       testClientID,
		clientSecret:   testClientSecret,
		authMethod:     httpclient.AuthMethodBasic,
		responseStatus: http.StatusOK,
		responseBody:   `{"access_token":"abc123"}`,
	}
	for _, opt := range opts {
		opt(settings)
	}

	fixture := &flowFixture{output: &bytes.Buffer{}}

	transport := mockTransport(func(req *http.Request) (*http.Response, error) {
		fixture.requests = append(fixture.requests, captureRequest(t, req))
		status, body := settings.responseStatus, settings.responseBody
		if route, ok := settings.routes[req.URL.String()]; ok {
			status, body = route.status, route.body
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Header:     make(http.Header),
		}, nil
	})

	logger := log.New(log.WithOutput(fixture.output, io.Discard))
	// The client keeps its own (discard) logger so the output buffer captures
	// the flow's output alone, independent of any client-side logging.
	client := httpclient.NewClient(&httpclient.Config{
		Transport: transport,
		Browser:   settings.browser,
		Listen:    settings.listen,
	})

	fixture.config = &Config{
		OIDC: OIDCConfig{
			ClientID:                           settings.clientID,
			ClientSecret:                       settings.clientSecret,
			AuthMethod:                         settings.authMethod,
			AuthorizationEndpoint:              testAuthorizationEndpoint,
			PushedAuthorizationRequestEndpoint: testPAREndpoint,
			DeviceAuthorizationEndpoint:        testDeviceAuthEndpoint,
			TokenEndpoint:                      testTokenEndpoint,
			IntrospectionEndpoint:              testIntrospectionEndpoint,
		},
		Runtime: Runtime{
			Client: client,
			Logger: logger,
		},
	}

	if settings.dpopKeys {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating DPoP key: %v", err)
		}
		fixture.config.DPoPKeys = DPoPKeys{Public: &priv.PublicKey, Private: priv}
		fixture.dpopPublicKey = &priv.PublicKey
	}

	return fixture
}

// captureRequest snapshots a request as the wire would carry it: method, URL, a
// copy of the headers, and the form body decoded from the request payload.
func captureRequest(t *testing.T, req *http.Request) *capturedRequest {
	t.Helper()

	captured := &capturedRequest{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: req.Header.Clone(),
	}

	if req.Body != nil {
		// The RoundTripper contract makes the transport responsible for closing
		// the request body; honor it even though these test bodies are NopClosers.
		defer func() { _ = req.Body.Close() }()
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parsing request form: %v", err)
		}
		captured.Form = form
	}
	return captured
}

// onlyRequest returns the single request the flow was expected to emit, failing
// if a different number crossed the wire.
func (f *flowFixture) onlyRequest(t *testing.T) *capturedRequest {
	t.Helper()
	if len(f.requests) != 1 {
		t.Fatalf("got %d emitted requests, want exactly 1", len(f.requests))
	}
	return f.requests[0]
}

// basicAuthHeader is the Authorization header value the fixture's default
// credentials produce under client_secret_basic.
func basicAuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testClientID+":"+testClientSecret))
}
