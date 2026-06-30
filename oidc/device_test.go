package oidc

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/crypto/cryptotest"
)

// The device flow is exercised end-to-end through Run: the device-authorization
// and polling-token calls ride the capture transport, and the verification-URI
// launch goes through an injected browser instead of the system browser.

// recordingBrowser captures the URL it is asked to open without launching
// anything, standing in for the system browser in device-flow tests.
type recordingBrowser struct {
	openedURL string
}

func (b *recordingBrowser) Open(rawURL string) error {
	b.openedURL = rawURL
	return nil
}

func TestDeviceFlowRun(t *testing.T) {
	t.Parallel()

	deviceAuthBody := `{"device_code":"dev-code-1","user_code":"WDJB-MJHT","verification_uri":"https://op.example.com/device","interval":5,"expires_in":1800}`

	browser := &recordingBrowser{}

	fixture := newReadyConfig(t,
		withBrowser(browser),
		withRoute(testDeviceAuthEndpoint, http.StatusOK, deviceAuthBody),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	)

	flow := &DeviceFlow{
		Config: fixture.config,
		FlowConfig: &DeviceFlowConfig{
			Scope: "openid",
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(fixture.requests) != 2 {
		t.Fatalf("got %d emitted requests, want 2 (device-auth + token)", len(fixture.requests))
	}
	deviceReq, tokenReq := fixture.requests[0], fixture.requests[1]

	// Device-authorization request: client_id and scope on the wire, no client
	// authentication header (the device-auth endpoint takes none here).
	if deviceReq.URL != testDeviceAuthEndpoint {
		t.Errorf("device-auth url = %q, want %q", deviceReq.URL, testDeviceAuthEndpoint)
	}
	if deviceReq.Method != http.MethodPost {
		t.Errorf("device-auth method = %q, want POST", deviceReq.Method)
	}
	wantDeviceForm := url.Values{
		"client_id": {testClientID},
		"scope":     {"openid"},
	}
	if !reflect.DeepEqual(deviceReq.Form, wantDeviceForm) {
		t.Errorf("device-auth form = %v, want %v", deviceReq.Form, wantDeviceForm)
	}

	// The verification URI is opened through the injected browser seam.
	if browser.openedURL != "https://op.example.com/device" {
		t.Errorf("opened URL = %q, want the verification uri", browser.openedURL)
	}

	// Polling token request: device_code grant, client authentication via Basic.
	if tokenReq.URL != testTokenEndpoint {
		t.Errorf("token url = %q, want %q", tokenReq.URL, testTokenEndpoint)
	}
	if tokenReq.Method != http.MethodPost {
		t.Errorf("token method = %q, want POST", tokenReq.Method)
	}
	if got := tokenReq.Header.Get("Authorization"); got != basicAuthHeader() {
		t.Errorf("token Authorization = %q, want %q", got, basicAuthHeader())
	}
	wantTokenForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"dev-code-1"},
	}
	if !reflect.DeepEqual(tokenReq.Form, wantTokenForm) {
		t.Errorf("token form = %v, want %v", tokenReq.Form, wantTokenForm)
	}

	wantOutput := `{
  "access_token": "abc123",
  "token_type": "Bearer"
}
`
	if got := fixture.output.String(); got != wantOutput {
		t.Errorf("output = %q, want %q", got, wantOutput)
	}
}

// TestDeviceFlowRunVerificationURIComplete pins the branch that prefers the
// complete verification URI (user code embedded) when the response carries one.
func TestDeviceFlowRunVerificationURIComplete(t *testing.T) {
	t.Parallel()

	deviceAuthBody := `{"device_code":"dev-code-1","user_code":"WDJB-MJHT","verification_uri":"https://op.example.com/device","verification_uri_complete":"https://op.example.com/device?user_code=WDJB-MJHT","interval":5,"expires_in":1800}`

	browser := &recordingBrowser{}

	fixture := newReadyConfig(t,
		withBrowser(browser),
		withRoute(testDeviceAuthEndpoint, http.StatusOK, deviceAuthBody),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"Bearer"}`),
	)

	flow := &DeviceFlow{
		Config:     fixture.config,
		FlowConfig: &DeviceFlowConfig{Scope: "openid"},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// With a complete URI present, that is the one opened, not the bare URI.
	if browser.openedURL != "https://op.example.com/device?user_code=WDJB-MJHT" {
		t.Errorf("opened URL = %q, want the verification_uri_complete", browser.openedURL)
	}
}

// TestDeviceFlowRunDPoP verifies the polling token request carries a valid DPoP
// proof bound to the configured key.
func TestDeviceFlowRunDPoP(t *testing.T) {
	t.Parallel()

	deviceAuthBody := `{"device_code":"dev-code-1","verification_uri":"https://op.example.com/device","interval":5,"expires_in":1800}`

	fixture := newReadyConfig(t,
		withDPoPKeys(),
		withBrowser(&recordingBrowser{}),
		withRoute(testDeviceAuthEndpoint, http.StatusOK, deviceAuthBody),
		withResponse(http.StatusOK, `{"access_token":"abc123","token_type":"DPoP"}`),
	)

	flow := &DeviceFlow{
		Config: fixture.config,
		FlowConfig: &DeviceFlowConfig{
			Scope: "openid",
			DPoP:  true,
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(fixture.requests) != 2 {
		t.Fatalf("got %d emitted requests, want 2 (device-auth + token)", len(fixture.requests))
	}
	tokenReq := fixture.requests[1]
	if tokenReq.URL != testTokenEndpoint {
		t.Errorf("token url = %q, want %q", tokenReq.URL, testTokenEndpoint)
	}

	// VerifyDPoPProof fails on an empty proof, so it doubles as the presence check.
	cryptotest.VerifyDPoPProof(t, tokenReq.Header.Get("DPoP"), fixture.dpopPublicKey, http.MethodPost, testTokenEndpoint)
}
