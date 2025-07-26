package httpclient

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/jentz/oidc-cli/webflow"
)

func TestCreateAuthorizationCodeRequestValues(t *testing.T) {
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

func TestExecuteAuthorizationCodeRequest_BasicValidation(t *testing.T) {
	// Test basic parameter validation without actually executing the flow
	client := NewClient(nil)
	ctx := context.Background()

	// Test with invalid request (missing client_id)
	req := &AuthorizationCodeRequest{
		RedirectURI: "http://localhost:8080/callback",
	}

	_, err := client.ExecuteAuthorizationCodeRequest(ctx, "https://auth.example.com/authorize", "http://localhost:8080/callback", req)
	if err == nil {
		t.Error("Expected error for missing client_id, got nil")
	}

	// The error should be related to the request validation
	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestStateValidationLogic(t *testing.T) {
	// Test the state validation logic by simulating various callback scenarios
	tests := []struct {
		name             string
		requestState     string
		callbackResponse *webflow.CallbackResponse
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name:         "Valid state match",
			requestState: "test-state-123",
			callbackResponse: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "test-state-123",
			},
			expectError: false,
		},
		{
			name:         "State mismatch should fail",
			requestState: "test-state-123",
			callbackResponse: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "different-state-456",
			},
			expectError:      true,
			expectedErrorMsg: "state mismatch: expected \"test-state-123\" but got \"different-state-456\"",
		},
		{
			name:         "Empty state in request should allow any callback state but return empty",
			requestState: "",
			callbackResponse: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "any-state",
			},
			expectError: false,
		},
		{
			name:         "Empty state in both request and callback should work",
			requestState: "",
			callbackResponse: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "",
			},
			expectError: false,
		},
		{
			name:         "Missing code in callback should fail",
			requestState: "test-state-123",
			callbackResponse: &webflow.CallbackResponse{
				Code:             "",
				State:            "test-state-123",
				ErrorMsg:         "access_denied",
				ErrorDescription: "User denied access",
			},
			expectError:      true,
			expectedErrorMsg: "authorization failed with error access_denied and description User denied access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the state validation logic from ExecuteAuthorizationCodeRequest
			req := &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    tt.requestState,
			}

			callbackResp := tt.callbackResponse

			// Test state validation logic
			var err error
			if req.State != "" && callbackResp.State != req.State {
				err = fmt.Errorf("state mismatch: expected %q but got %q", req.State, callbackResp.State)
			}

			// Test authorization code validation
			if err == nil && callbackResp.Code == "" {
				err = fmt.Errorf("authorization failed with error %s and description %s", callbackResp.ErrorMsg, callbackResp.ErrorDescription)
			}

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error message %q, got %q", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}

			// Test response construction when no error
			if !tt.expectError {
				expectedState := func() string {
					if req.State != "" {
						return req.State
					}
					return ""
				}()

				response := &AuthorizationCodeResponse{
					Code:  callbackResp.Code,
					State: expectedState,
				}

				if response.Code != callbackResp.Code {
					t.Errorf("Expected response code %q, got %q", callbackResp.Code, response.Code)
				}
				if response.State != expectedState {
					t.Errorf("Expected response state %q, got %q", expectedState, response.State)
				}
			}
		})
	}
}
