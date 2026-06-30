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

func TestClientCredentialsFlowRun(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t,
		withResponse(http.StatusOK, `{"access_token":"abc123","expires_in":3600,"token_type":"Bearer"}`))

	flow := &ClientCredentialsFlow{
		Config:     fixture.config,
		FlowConfig: &ClientCredentialsFlowConfig{Scope: "read write"},
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
		"grant_type": {"client_credentials"},
		"scope":      {"read write"},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Errorf("form = %v, want %v", req.Form, wantForm)
	}

	wantOutput := `{
  "access_token": "abc123",
  "expires_in": 3600,
  "token_type": "Bearer"
}
`
	if got := fixture.output.String(); got != wantOutput {
		t.Errorf("output = %q, want %q", got, wantOutput)
	}
}

func TestClientCredentialsFlowRunServerError(t *testing.T) {
	t.Parallel()

	fixture := newReadyConfig(t,
		withResponse(http.StatusBadRequest, `{"error":"invalid_client","error_description":"bad credentials"}`))

	flow := &ClientCredentialsFlow{
		Config:     fixture.config,
		FlowConfig: &ClientCredentialsFlowConfig{},
	}

	err := flow.Run(context.Background())
	if !errors.Is(err, httpclient.ErrOAuthError) {
		t.Fatalf("Run() error = %v, want errors.Is(..., httpclient.ErrOAuthError)", err)
	}

	// The request is still emitted; only the response surfaces as an error.
	fixture.onlyRequest(t)
	if got := fixture.output.String(); got != "" {
		t.Errorf("output = %q, want empty on error", got)
	}
}
