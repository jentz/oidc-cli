package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/httpclient"
)

func TestIntrospectFlowRun(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t,
		withResponse(http.StatusOK, `{"active":true,"client_id":"test-client","scope":"read write"}`))

	flow := &IntrospectFlow{
		Config: fixture.config,
		FlowConfig: &IntrospectFlowConfig{
			Token:         "token-to-inspect",
			TokenTypeHint: "access_token",
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	req := fixture.onlyRequest(t)
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL != testIntrospectionEndpoint {
		t.Errorf("url = %q, want %q", req.URL, testIntrospectionEndpoint)
	}
	if got := req.Header.Get("Authorization"); got != basicAuthHeader() {
		t.Errorf("Authorization = %q, want %q", got, basicAuthHeader())
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want application/json", got)
	}

	wantForm := url.Values{
		"token":           {"token-to-inspect"},
		"token_type_hint": {"access_token"},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Errorf("form = %v, want %v", req.Form, wantForm)
	}

	wantOutput := `{
  "active": true,
  "client_id": "test-client",
  "scope": "read write"
}
`
	if got := fixture.output.String(); got != wantOutput {
		t.Errorf("output = %q, want %q", got, wantOutput)
	}
}

// TestIntrospectFlowRunPostAuth characterizes client_secret_post: credentials
// ride in the form body and a custom Accept media type is honored.
func TestIntrospectFlowRunPostAuth(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t, withAuthMethod(httpclient.AuthMethodPost),
		withResponse(http.StatusOK, `{"active":false}`))

	flow := &IntrospectFlow{
		Config: fixture.config,
		FlowConfig: &IntrospectFlowConfig{
			Token:           "token-to-inspect",
			AcceptMediaType: "application/token-introspection+jwt",
		},
	}

	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	req := fixture.onlyRequest(t)
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL != testIntrospectionEndpoint {
		t.Errorf("url = %q, want %q", req.URL, testIntrospectionEndpoint)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty for client_secret_post", got)
	}
	if got := req.Header.Get("Accept"); got != "application/token-introspection+jwt" {
		t.Errorf("Accept = %q, want application/token-introspection+jwt", got)
	}

	wantForm := url.Values{
		"token":         {"token-to-inspect"},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Errorf("form = %v, want %v", req.Form, wantForm)
	}
}

func TestIntrospectFlowRunServerError(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t,
		withResponse(http.StatusUnauthorized, `{"error":"invalid_token"}`))

	flow := &IntrospectFlow{
		Config:     fixture.config,
		FlowConfig: &IntrospectFlowConfig{Token: "token-to-inspect"},
	}

	err := flow.Run(context.Background())
	if !errors.Is(err, httpclient.ErrOAuthError) {
		t.Fatalf("Run() error = %v, want errors.Is(..., httpclient.ErrOAuthError)", err)
	}

	fixture.onlyRequest(t)
	if got := fixture.output.String(); got != "" {
		t.Errorf("output = %q, want empty on error", got)
	}
}
