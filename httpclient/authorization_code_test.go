package httpclient

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/webflow"
)

func TestCreateAuthorizationCodeRequestValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		req        *AuthorizationCodeRequest
		wantErr    bool
		wantParams map[string]string
	}{
		{
			name: "minimal required fields",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type": "code",
				"client_id":     "test-client",
			},
		},
		{
			name: "all standard fields",
			req: &AuthorizationCodeRequest{
				ClientID:            "test-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid profile email",
				State:               "random-state-123",
				Prompt:              "consent",
				AcrValues:           "level1 level2",
				LoginHint:           "user@example.com",
				MaxAge:              "3600",
				UILocales:           "en-US",
				CodeChallengeMethod: "S256",
				CodeChallenge:       "challenge123",
				RequestURI:          "urn:ietf:params:oauth:request_uri:example",
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type":         "code",
				"client_id":             "test-client",
				"redirect_uri":          "https://example.com/callback",
				"scope":                 "openid profile email",
				"state":                 "random-state-123",
				"prompt":                "consent",
				"acr_values":            "level1 level2",
				"login_hint":            "user@example.com",
				"max_age":               "3600",
				"ui_locales":            "en-US",
				"code_challenge_method": "S256",
				"code_challenge":        "challenge123",
				"request_uri":           "urn:ietf:params:oauth:request_uri:example",
			},
		},
		{
			name: "with custom arguments",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				CustomArgs: &CustomArgs{
					"custom_param":  "custom_value",
					"another_param": "another_value",
				},
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type": "code",
				"client_id":     "test-client",
				"custom_param":  "custom_value",
				"another_param": "another_value",
			},
		},
		{
			name: "missing client_id",
			req: &AuthorizationCodeRequest{
				RedirectURI: "https://example.com/callback",
				Scope:       "openid",
			},
			wantErr: true,
		},
		{
			name: "empty client_id",
			req: &AuthorizationCodeRequest{
				ClientID: "",
				Scope:    "openid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			values, err := CreateAuthorizationCodeRequestValues(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check all expected parameters
			for key, want := range tt.wantParams {
				got := values.Get(key)
				if got != want {
					t.Errorf("got param %s=%q, want %q", key, got, want)
				}
			}

			// Check that unexpected parameters are not set
			if values.Get("redirect_uri") != tt.req.RedirectURI {
				t.Errorf("redirect_uri mismatch: got %q, want %q", values.Get("redirect_uri"), tt.req.RedirectURI)
			}
		})
	}
}

func TestCreateAuthorizationCodeRequestURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		values   *url.Values
		wantErr  bool
		wantURL  string
	}{
		{
			name:     "valid endpoint and values",
			endpoint: "https://auth.example.com/authorize",
			values: &url.Values{
				"response_type": []string{"code"},
				"client_id":     []string{"test-client"},
				"scope":         []string{"openid profile"},
			},
			wantErr: false,
			wantURL: "https://auth.example.com/authorize?client_id=test-client&response_type=code&scope=openid+profile",
		},
		{
			name:     "endpoint with existing query params",
			endpoint: "https://auth.example.com/authorize?existing=param",
			values: &url.Values{
				"response_type": []string{"code"},
				"client_id":     []string{"test-client"},
			},
			wantErr: false,
			wantURL: "https://auth.example.com/authorize?client_id=test-client&response_type=code",
		},
		{
			name:     "empty endpoint",
			endpoint: "",
			values: &url.Values{
				"response_type": []string{"code"},
			},
			wantErr: true,
		},
		{
			name:     "nil values",
			endpoint: "https://auth.example.com/authorize",
			values:   nil,
			wantErr:  true,
		},
		{
			name:     "invalid endpoint URL",
			endpoint: "://invalid-url",
			values: &url.Values{
				"response_type": []string{"code"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotURL, err := CreateAuthorizationCodeRequestURL(tt.endpoint, tt.values)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Parse both URLs to compare them properly (query param order may vary)
			gotParsed, err := url.Parse(gotURL)
			if err != nil {
				t.Fatalf("Failed to parse result URL: %v", err)
			}

			wantParsed, err := url.Parse(tt.wantURL)
			if err != nil {
				t.Fatalf("Failed to parse expected URL: %v", err)
			}

			// Compare scheme, host, and path
			if gotParsed.Scheme != wantParsed.Scheme {
				t.Errorf("got scheme %q, want %q", gotParsed.Scheme, wantParsed.Scheme)
			}
			if gotParsed.Host != wantParsed.Host {
				t.Errorf("got host %q, want %q", gotParsed.Host, wantParsed.Host)
			}
			if gotParsed.Path != wantParsed.Path {
				t.Errorf("got path %q, want %q", gotParsed.Path, wantParsed.Path)
			}

			// Compare query parameters
			gotQuery := gotParsed.Query()
			wantQuery := wantParsed.Query()

			for key, wantVals := range wantQuery {
				gotVals := gotQuery[key]
				if len(gotVals) != len(wantVals) {
					t.Errorf("param %s: got %d values, want %d", key, len(gotVals), len(wantVals))
					continue
				}
				for i, wantVal := range wantVals {
					if gotVals[i] != wantVal {
						t.Errorf("param %s[%d]: got %q, want %q", key, i, gotVals[i], wantVal)
					}
				}
			}
		})
	}
}

// TestBuildAuthorizationURL covers the guards and rendering of the unexported
// helper that ExecuteAuthorizationCodeRequest uses to turn a request into the
// URL handed to the browser.
func TestBuildAuthorizationURL(t *testing.T) {
	t.Parallel()

	t.Run("renders the request as query parameters", func(t *testing.T) {
		t.Parallel()
		got, err := buildAuthorizationURL("https://auth.example.com/authorize", &AuthorizationCodeRequest{
			ClientID: "test-client",
			State:    "abc",
			Scope:    "openid",
		})
		if err != nil {
			t.Fatalf("buildAuthorizationURL() error = %v", err)
		}
		parsed, err := url.Parse(got)
		if err != nil {
			t.Fatalf("parsing result URL: %v", err)
		}
		if parsed.Host != "auth.example.com" || parsed.Path != "/authorize" {
			t.Errorf("endpoint = %q, want host auth.example.com path /authorize", got)
		}
		q := parsed.Query()
		for key, want := range map[string]string{
			"response_type": "code",
			"client_id":     "test-client",
			"state":         "abc",
			"scope":         "openid",
		} {
			if q.Get(key) != want {
				t.Errorf("query %s = %q, want %q", key, q.Get(key), want)
			}
		}
	})

	tests := []struct {
		name     string
		endpoint string
		req      *AuthorizationCodeRequest
		wantErr  string
	}{
		{
			name:     "empty endpoint",
			endpoint: "",
			req:      &AuthorizationCodeRequest{ClientID: "test-client"},
			wantErr:  "endpoint is required",
		},
		{
			name:     "nil request",
			endpoint: "https://auth.example.com/authorize",
			req:      nil,
			wantErr:  "request cannot be nil",
		},
		{
			name:     "missing client_id surfaces the values error",
			endpoint: "https://auth.example.com/authorize",
			req:      &AuthorizationCodeRequest{State: "abc"},
			wantErr:  "failed to create authorization request values",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildAuthorizationURL(tt.endpoint, tt.req)
			if err == nil {
				t.Fatalf("buildAuthorizationURL() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCallbackResponse exercises the real CSRF/state and
// authorization-code validation inlined into ExecuteAuthorizationCodeRequest.
func TestValidateCallbackResponse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		reqState  string
		resp      *webflow.CallbackResponse
		wantCode  string
		wantState string
		wantErr   string
	}{
		{
			name:      "state matches",
			reqState:  "test-state-123",
			resp:      &webflow.CallbackResponse{Code: "auth-code-123", State: "test-state-123"},
			wantCode:  "auth-code-123",
			wantState: "test-state-123",
		},
		{
			name:     "state mismatch is rejected",
			reqState: "test-state-123",
			resp:     &webflow.CallbackResponse{Code: "auth-code-123", State: "different-state-456"},
			wantErr:  `state mismatch: expected "test-state-123" but got "different-state-456"`,
		},
		{
			name:      "empty request state accepts any callback state and returns empty",
			reqState:  "",
			resp:      &webflow.CallbackResponse{Code: "auth-code-123", State: "any-state"},
			wantCode:  "auth-code-123",
			wantState: "",
		},
		{
			name:     "missing code reports the authorization error",
			reqState: "test-state-123",
			resp: &webflow.CallbackResponse{
				State:            "test-state-123",
				ErrorMsg:         "access_denied",
				ErrorDescription: "User denied access",
			},
			wantErr: "authorization failed with error access_denied and description User denied access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &AuthorizationCodeRequest{ClientID: "test-client", State: tt.reqState}
			got, err := validateCallbackResponse(req, tt.resp)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateCallbackResponse() error = nil, want %q", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
				}
				if got != nil {
					t.Errorf("response = %+v, want nil on error", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("validateCallbackResponse() error = %v", err)
			}
			if got.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.State != tt.wantState {
				t.Errorf("state = %q, want %q", got.State, tt.wantState)
			}
		})
	}

	t.Run("nil request and response are guarded", func(t *testing.T) {
		t.Parallel()
		if _, err := validateCallbackResponse(nil, &webflow.CallbackResponse{}); err == nil || err.Error() != "request cannot be nil" {
			t.Errorf("nil request: error = %v, want \"request cannot be nil\"", err)
		}
		if _, err := validateCallbackResponse(&AuthorizationCodeRequest{}, nil); err == nil || err.Error() != "response cannot be nil" {
			t.Errorf("nil response: error = %v, want \"response cannot be nil\"", err)
		}
	})
}

// TestStartCallbackServerGuards covers the early returns that reject a request
// before any listener is bound: an empty callback and an already-cancelled
// context.
func TestStartCallbackServerGuards(t *testing.T) {
	t.Parallel()
	client := NewClient(nil)

	t.Run("empty callback is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := client.startCallbackServer(context.Background(), "")
		if err == nil || err.Error() != "callback URL is required" {
			t.Errorf("error = %v, want \"callback URL is required\"", err)
		}
	})

	t.Run("cancelled context is honored", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.startCallbackServer(ctx, "http://127.0.0.1:0/callback")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	})

	t.Run("invalid callback URI fails to create the server", func(t *testing.T) {
		t.Parallel()
		_, err := client.startCallbackServer(context.Background(), "://bad")
		if err == nil {
			t.Fatal("error = nil, want a callback-server creation error")
		}
		if !strings.Contains(err.Error(), "failed to create callback server") {
			t.Errorf("error = %q, want it to contain %q", err, "failed to create callback server")
		}
	})
}
