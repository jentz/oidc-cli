//go:build acceptance

package acceptance

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const (
	expectedDeviceCode = "sensitive-device-code"
	expectedUserCode   = "ACPT-1234"
)

type deviceAuthorizationRequest struct {
	Method   string
	ClientID string
	Scope    string
}

type deviceTokenResponse struct {
	status int
	body   map[string]any
}

type deviceProvider struct {
	server *httptest.Server

	pollResponses []deviceTokenResponse

	mu                   sync.Mutex
	discoveryRequests    int
	deviceAuthRequests   []deviceAuthorizationRequest
	tokenRequests        []tokenRequest
	tokenRequestTimes    []time.Time
	tokenResponseCounter int
}

func newDeviceProvider(t *testing.T, pollResponses []deviceTokenResponse) *deviceProvider {
	t.Helper()

	provider := &deviceProvider{pollResponses: pollResponses}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/device_authorization", provider.handleDeviceAuthorization)
	mux.HandleFunc("/token", provider.handleToken)

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *deviceProvider) issuer() string {
	return p.server.URL
}

func (p *deviceProvider) requests() (int, []deviceAuthorizationRequest, []tokenRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	deviceAuthRequests := make([]deviceAuthorizationRequest, len(p.deviceAuthRequests))
	copy(deviceAuthRequests, p.deviceAuthRequests)
	tokenRequests := make([]tokenRequest, len(p.tokenRequests))
	copy(tokenRequests, p.tokenRequests)

	return p.discoveryRequests, deviceAuthRequests, tokenRequests
}

func (p *deviceProvider) tokenPollGap() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.tokenRequestTimes) != 2 {
		return 0
	}
	return p.tokenRequestTimes[1].Sub(p.tokenRequestTimes[0])
}

func (p *deviceProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	p.discoveryRequests++
	p.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                        p.server.URL,
		"device_authorization_endpoint": p.server.URL + "/device_authorization",
		"token_endpoint":                p.server.URL + "/token",
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post",
		},
	})
}

func (p *deviceProvider) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	request := deviceAuthorizationRequest{
		Method:   r.Method,
		ClientID: r.PostForm.Get("client_id"),
		Scope:    r.PostForm.Get("scope"),
	}

	p.mu.Lock()
	p.deviceAuthRequests = append(p.deviceAuthRequests, request)
	p.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      expectedDeviceCode,
		"user_code":        expectedUserCode,
		"verification_uri": p.server.URL + "/activate",
		"expires_in":       1800,
		"interval":         1,
	})
}

func (p *deviceProvider) handleToken(w http.ResponseWriter, r *http.Request) {
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
		DeviceCode:    r.PostForm.Get("device_code"),
	}

	p.mu.Lock()
	p.tokenRequests = append(p.tokenRequests, request)
	p.tokenRequestTimes = append(p.tokenRequestTimes, time.Now())
	responseIndex := p.tokenResponseCounter
	p.tokenResponseCounter++
	p.mu.Unlock()

	if responseIndex >= len(p.pollResponses) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": "unexpected extra poll",
		})
		return
	}

	response := p.pollResponses[responseIndex]
	writeJSON(w, response.status, response.body)
}

func successfulDeviceToken(accessToken string) deviceTokenResponse {
	return deviceTokenResponse{
		status: http.StatusOK,
		body: map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "openid profile",
		},
	}
}

func pendingDeviceToken() deviceTokenResponse {
	return deviceTokenResponse{
		status: http.StatusBadRequest,
		body: map[string]any{
			"error": "authorization_pending",
		},
	}
}

func rejectedDeviceToken() deviceTokenResponse {
	return deviceTokenResponse{
		status: http.StatusBadRequest,
		body: map[string]any{
			"error":             "access_denied",
			"error_description": "the user rejected the device authorization",
		},
	}
}

func runDeviceFlow(t *testing.T, provider *deviceProvider) Result {
	t.Helper()

	return Run(t,
		"--no-browser",
		"device",
		"--issuer", provider.issuer(),
		"--client-id", expectedClientID,
		"--client-secret", expectedClientSecret,
		"--auth-method", "client_secret_post",
		"--scope", "openid profile",
	)
}

func assertDeviceFlowRequests(t *testing.T, provider *deviceProvider, expectedPolls int) {
	t.Helper()

	discoveryRequests, deviceRequests, tokenRequests := provider.requests()
	assertEqual(t, discoveryRequests, 1, "discovery request count")
	if len(deviceRequests) != 1 {
		t.Fatalf("expected 1 device authorization request, got %d: %#v", len(deviceRequests), deviceRequests)
	}
	assertEqual(t, deviceRequests[0].Method, http.MethodPost, "device authorization request method")
	assertEqual(t, deviceRequests[0].ClientID, expectedClientID, "device authorization client_id")
	assertEqual(t, deviceRequests[0].Scope, "openid profile", "device authorization scope")

	if len(tokenRequests) != expectedPolls {
		t.Fatalf("expected %d token requests, got %d: %#v", expectedPolls, len(tokenRequests), tokenRequests)
	}
	for _, request := range tokenRequests {
		assertEqual(t, request.Method, http.MethodPost, "token request method")
		assertEqual(t, request.Authorization, "", "authorization header")
		assertEqual(t, request.GrantType, "urn:ietf:params:oauth:grant-type:device_code", "grant_type")
		assertEqual(t, request.ClientID, expectedClientID, "token client_id")
		assertEqual(t, request.ClientSecret, expectedClientSecret, "token client_secret")
		assertEqual(t, request.DeviceCode, expectedDeviceCode, "device_code")
	}
}

func assertNoBrowserDeviceInstructions(t *testing.T, result Result, provider *deviceProvider) {
	t.Helper()

	assertContains(t, result.Stderr, "Open this URL in a browser to authorize the device:\n"+provider.issuer()+"/activate", "stderr")
	assertContains(t, result.Stderr, "Enter this code:\n"+expectedUserCode, "stderr")
}

func TestDeviceFlowPendingThenSuccess(t *testing.T) {
	provider := newDeviceProvider(t, []deviceTokenResponse{
		pendingDeviceToken(),
		successfulDeviceToken("acceptance-device-access-token"),
	})

	result := runDeviceFlow(t, provider)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}
	pollGap := provider.tokenPollGap()
	if pollGap < time.Second {
		t.Fatalf("expected pending poll to wait at least 1s, waited %s", pollGap)
	}
	if pollGap > 3*time.Second {
		t.Fatalf("expected pending poll to honor the 1s provider interval, waited %s", pollGap)
	}
	assertNoBrowserDeviceInstructions(t, result, provider)
	token := result.JSON(t)
	assertEqual(t, token["access_token"], "acceptance-device-access-token", "access_token")
	assertEqual(t, token["token_type"], "Bearer", "token_type")
	assertEqual(t, token["expires_in"], float64(3600), "expires_in")
	assertEqual(t, token["scope"], "openid profile", "scope")
	assertDeviceFlowRequests(t, provider, 2)
}

func TestDeviceFlowImmediateSuccess(t *testing.T) {
	provider := newDeviceProvider(t, []deviceTokenResponse{
		successfulDeviceToken("acceptance-device-immediate-token"),
	})

	result := runDeviceFlow(t, provider)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr:\n%s\nstdout:\n%s", result.ExitCode, result.Stderr, result.Stdout)
	}
	assertNoBrowserDeviceInstructions(t, result, provider)
	token := result.JSON(t)
	assertEqual(t, token["access_token"], "acceptance-device-immediate-token", "access_token")
	assertEqual(t, token["token_type"], "Bearer", "token_type")
	assertEqual(t, token["expires_in"], float64(3600), "expires_in")
	assertEqual(t, token["scope"], "openid profile", "scope")
	assertDeviceFlowRequests(t, provider, 1)
}

func TestDeviceFlowProviderRejection(t *testing.T) {
	provider := newDeviceProvider(t, []deviceTokenResponse{
		rejectedDeviceToken(),
	})

	result := runDeviceFlow(t, provider)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code\nstdout:\n%s\nstderr:\n%s", result.Stdout, result.Stderr)
	}
	assertEqual(t, result.Stdout, "", "stdout")
	assertNoBrowserDeviceInstructions(t, result, provider)
	assertContains(t, result.Stderr, "polling token request failed", "stderr")
	assertContains(t, result.Stderr, "access_denied", "stderr")
	assertContains(t, result.Stderr, "the user rejected the device authorization", "stderr")
	assertNotContains(t, result.Stderr, expectedClientSecret, "stderr")
	assertNotContains(t, result.Stderr, expectedDeviceCode, "stderr")
	assertNotContains(t, result.Stdout, expectedClientSecret, "stdout")
	assertNotContains(t, result.Stdout, expectedDeviceCode, "stdout")
	assertDeviceFlowRequests(t, provider, 1)
}
