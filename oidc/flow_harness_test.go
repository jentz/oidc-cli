package oidc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

// The four non-interactive flows are exercised through their Run entry point
// against this harness. Tests assert only on what crosses the Run seam — the
// HTTP request emitted (method, URL, headers, form body) and the bytes written
// to output — never on config internals or unexported helpers. A later split
// of the Config struct touches only newReadyConfig (a compile error if missed),
// not the per-flow assertions, which keep passing on the same wire and output.

const (
	testClientID              = "test-client"
	testClientSecret          = "test-secret"
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
// no lock because each non-interactive flow drives one synchronous request;
// capturing concurrent requests would require synchronizing this append.
type flowFixture struct {
	config   *Config
	requests []*capturedRequest
	output   *bytes.Buffer

	// dpopPublicKey is the key the fixture's DPoP proofs are bound to, set only
	// when withDPoPKeys is used, so tests can verify the emitted proof.
	dpopPublicKey any
}

type fixtureSettings struct {
	clientID       string
	clientSecret   string
	authMethod     httpclient.AuthMethod
	dpopKeys       bool
	responseStatus int
	responseBody   string
}

type fixtureOption func(*fixtureSettings)

// withAuthMethod overrides the client authentication method (default Basic).
func withAuthMethod(m httpclient.AuthMethod) fixtureOption {
	return func(s *fixtureSettings) { s.authMethod = m }
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
		return &http.Response{
			StatusCode: settings.responseStatus,
			Body:       io.NopCloser(bytes.NewBufferString(settings.responseBody)),
			Header:     make(http.Header),
		}, nil
	})

	logger := log.New(log.WithOutput(fixture.output, io.Discard))
	// The client keeps its own (discard) logger so the output buffer captures
	// the flow's output alone; the exact-output assertions stay scoped to the
	// Run seam rather than coupling to any future client-side logging.
	client := httpclient.NewClient(&httpclient.Config{
		Transport: transport,
	})

	fixture.config = &Config{
		ClientID:              settings.clientID,
		ClientSecret:          settings.clientSecret,
		AuthMethod:            settings.authMethod,
		TokenEndpoint:         testTokenEndpoint,
		IntrospectionEndpoint: testIntrospectionEndpoint,
		Client:                client,
		Logger:                logger,
	}

	if settings.dpopKeys {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating DPoP key: %v", err)
		}
		fixture.config.DPoPPublicKey = &priv.PublicKey
		fixture.config.DPoPPrivateKey = priv
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
