package oidc

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/crypto/cryptotest"
)

func TestTokenExchangeFlowRun(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t,
		withResponse(http.StatusOK, `{"access_token":"exchanged","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`))

	flow := &TokenExchangeFlow{
		Config: fixture.config,
		FlowConfig: &TokenExchangeFlowConfig{
			SubjectToken:       "subject-token",
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
			RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			Audience:           "https://api.example.com",
			Scope:              "read",
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	req := fixture.onlyRequest(t)
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL != testTokenEndpoint {
		t.Errorf("url = %q, want %q", req.URL, testTokenEndpoint)
	}
	if got := req.Header.Get("Authorization"); got != basicAuthHeader() {
		t.Errorf("Authorization = %q, want %q", got, basicAuthHeader())
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}

	wantForm := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {"subject-token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":             {"https://api.example.com"},
		"scope":                {"read"},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Errorf("form = %v, want %v", req.Form, wantForm)
	}

	wantOutput := `{
  "access_token": "exchanged",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer"
}
`
	if got := fixture.output.String(); got != wantOutput {
		t.Errorf("output = %q, want %q", got, wantOutput)
	}
}

func TestTokenExchangeFlowRunDPoP(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t, withDPoPKeys(),
		withResponse(http.StatusOK, `{"access_token":"exchanged","token_type":"DPoP"}`))

	flow := &TokenExchangeFlow{
		Config: fixture.config,
		FlowConfig: &TokenExchangeFlowConfig{
			SubjectToken:     "subject-token",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			DPoP:             true,
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	req := fixture.onlyRequest(t)
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL != testTokenEndpoint {
		t.Errorf("url = %q, want %q", req.URL, testTokenEndpoint)
	}

	// Client authentication and content type must survive on the DPoP path,
	// not just the proof header — a DPoP-specific regression could drop them.
	if got := req.Header.Get("Authorization"); got != basicAuthHeader() {
		t.Errorf("Authorization = %q, want %q", got, basicAuthHeader())
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}

	// The form must stay intact on the DPoP path, not just the proof header.
	wantForm := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"subject-token"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Errorf("form = %v, want %v", req.Form, wantForm)
	}

	// VerifyDPoPProof fails on an empty proof, so it doubles as the presence check.
	cryptotest.VerifyDPoPProof(t, req.Header.Get("DPoP"), fixture.dpopPublicKey, http.MethodPost, testTokenEndpoint)
}

// TestTokenExchangeFlowRunDPoPWithoutKeys pins the current behavior that asking
// for DPoP without loaded keys fails at send time, before any request is made.
func TestTokenExchangeFlowRunDPoPWithoutKeys(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t)

	flow := &TokenExchangeFlow{
		Config: fixture.config,
		FlowConfig: &TokenExchangeFlowConfig{
			SubjectToken:     "subject-token",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			DPoP:             true,
		},
	}

	err := flow.Run(context.Background())
	if err == nil {
		t.Fatal("Run() error = nil, want error for DPoP with absent keys")
	}
	// Pin that the failure is the proof generation, not some incidental error.
	if !strings.Contains(err.Error(), "DPoP proof") {
		t.Errorf("error = %q, want it to mention DPoP proof generation", err)
	}

	if len(fixture.requests) != 0 {
		t.Errorf("emitted %d requests, want 0 when proof generation fails", len(fixture.requests))
	}
	if got := fixture.output.String(); got != "" {
		t.Errorf("output = %q, want empty on error", got)
	}
}
