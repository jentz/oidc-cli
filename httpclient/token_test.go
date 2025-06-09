package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExecuteTokenRequest(t *testing.T) {
	tests := []struct {
		name       string
		req        *TokenRequest
		wantParams map[string]string
		wantAuth   string
	}{
		{
			name: "basic auth method",
			req: &TokenRequest{
				GrantType:    "authorization_code",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthMethod:   AuthMethodBasic,
				Params:       url.Values{"code": []string{"auth-code"}},
			},
			wantParams: map[string]string{
				"grant_type": "authorization_code",
				"code":       "auth-code",
			},
			wantAuth: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=", // base64 of test-client:test-secret
		},
		{
			name: "post auth method",
			req: &TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthMethod:   AuthMethodPost,
			},
			wantParams: map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		},
		{
			name: "none auth method",
			req: &TokenRequest{
				GrantType:  "authorization_code",
				ClientID:   "public-client",
				AuthMethod: AuthMethodNone,
				Params:     url.Values{"code": []string{"auth-code"}},
			},
			wantParams: map[string]string{
				"grant_type": "authorization_code",
				"client_id":  "public-client",
				"code":       "auth-code",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST method, got %s", r.Method)
				}

				// Check auth header if expected
				if tt.wantAuth != "" {
					gotAuth := r.Header.Get("Authorization")
					if gotAuth != tt.wantAuth {
						t.Errorf("got Authorization header %q, want %q", gotAuth, tt.wantAuth)
					}
				}

				// Parse form and check parameters
				_ = r.ParseForm()
				for key, want := range tt.wantParams {
					got := r.FormValue(key)
					if got != want {
						t.Errorf("got param %s=%q, want %q", key, got, want)
					}
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"token123","token_type":"Bearer"}`))
			}))
			defer ts.Close()

			client := NewClient(nil)
			resp, err := client.ExecuteTokenRequest(context.Background(), ts.URL, tt.req, nil)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !resp.IsSuccess() {
				t.Errorf("Expected successful response, got status %d", resp.StatusCode)
			}
		})
	}
}

func TestCreateAuthCodeTokenRequest(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		authMethod   AuthMethod
		code         string
		redirectURI  string
		codeVerifier string
		wantParams   map[string]string
	}{
		{
			name:         "with code verifier",
			clientID:     "test-client",
			clientSecret: "secret",
			authMethod:   AuthMethodBasic,
			code:         "auth-code-123",
			redirectURI:  "https://example.com/callback",
			codeVerifier: "verifier123",
			wantParams: map[string]string{
				"code":          "auth-code-123",
				"redirect_uri":  "https://example.com/callback",
				"code_verifier": "verifier123",
			},
		},
		{
			name:         "without code verifier",
			clientID:     "test-client",
			clientSecret: "secret",
			authMethod:   AuthMethodPost,
			code:         "auth-code-456",
			redirectURI:  "https://example.com/callback",
			codeVerifier: "",
			wantParams: map[string]string{
				"code":         "auth-code-456",
				"redirect_uri": "https://example.com/callback",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CreateAuthCodeTokenRequest(tt.clientID, tt.clientSecret, tt.authMethod, tt.code, tt.redirectURI, tt.codeVerifier)

			// Check basic fields
			if req.GrantType != "authorization_code" {
				t.Errorf("got GrantType %q, want %q", req.GrantType, "authorization_code")
			}
			if req.ClientID != tt.clientID {
				t.Errorf("got ClientID %q, want %q", req.ClientID, tt.clientID)
			}
			if req.ClientSecret != tt.clientSecret {
				t.Errorf("got ClientSecret %q, want %q", req.ClientSecret, tt.clientSecret)
			}
			if req.AuthMethod != tt.authMethod {
				t.Errorf("got AuthMethod %v, want %v", req.AuthMethod, tt.authMethod)
			}

			// Check params
			for key, want := range tt.wantParams {
				got := req.Params.Get(key)
				if got != want {
					t.Errorf("got param %s=%q, want %q", key, got, want)
				}
			}

			// Check that code_verifier is not set when empty
			if tt.codeVerifier == "" && req.Params.Get("code_verifier") != "" {
				t.Error("code_verifier should not be set when empty")
			}
		})
	}
}

func TestCreateRefreshTokenRequest(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		authMethod   AuthMethod
		refreshToken string
		scope        string
		wantParams   map[string]string
	}{
		{
			name:         "with scope",
			clientID:     "test-client",
			clientSecret: "secret",
			authMethod:   AuthMethodBasic,
			refreshToken: "refresh123",
			scope:        "openid profile",
			wantParams: map[string]string{
				"refresh_token": "refresh123",
				"scope":         "openid profile",
			},
		},
		{
			name:         "without scope",
			clientID:     "test-client",
			clientSecret: "secret",
			authMethod:   AuthMethodPost,
			refreshToken: "refresh456",
			scope:        "",
			wantParams: map[string]string{
				"refresh_token": "refresh456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CreateRefreshTokenRequest(tt.clientID, tt.clientSecret, tt.authMethod, tt.refreshToken, tt.scope)

			// Check basic fields
			if req.GrantType != "refresh_token" {
				t.Errorf("got GrantType %q, want %q", req.GrantType, "refresh_token")
			}

			// Check params
			for key, want := range tt.wantParams {
				got := req.Params.Get(key)
				if got != want {
					t.Errorf("got param %s=%q, want %q", key, got, want)
				}
			}

			// Check that scope is not set when empty
			if tt.scope == "" && req.Params.Get("scope") != "" {
				t.Error("scope should not be set when empty")
			}
		})
	}
}

func TestCreateClientCredentialsRequest(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		authMethod   AuthMethod
		scope        string
		wantParams   map[string]string
	}{
		{
			name:         "with scope",
			clientID:     "client123",
			clientSecret: "secret456",
			authMethod:   AuthMethodBasic,
			scope:        "read write",
			wantParams: map[string]string{
				"scope": "read write",
			},
		},
		{
			name:         "without scope",
			clientID:     "client789",
			clientSecret: "secret012",
			authMethod:   AuthMethodPost,
			scope:        "",
			wantParams:   map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CreateClientCredentialsRequest(tt.clientID, tt.clientSecret, tt.authMethod, tt.scope)

			// Check basic fields
			if req.GrantType != "client_credentials" {
				t.Errorf("got GrantType %q, want %q", req.GrantType, "client_credentials")
			}

			// Check params
			for key, want := range tt.wantParams {
				got := req.Params.Get(key)
				if got != want {
					t.Errorf("got param %s=%q, want %q", key, got, want)
				}
			}

			// Check that scope is not set when empty
			if tt.scope == "" && req.Params.Get("scope") != "" {
				t.Error("scope should not be set when empty")
			}
		})
	}
}

func TestCreateDeviceCodeTokenRequest(t *testing.T) {
	req := CreateDeviceCodeTokenRequest("device-client", "device-secret", AuthMethodBasic, "device123")

	// Check basic fields
	wantGrantType := "urn:ietf:params:oauth:grant-type:device_code"
	if req.GrantType != wantGrantType {
		t.Errorf("got GrantType %q, want %q", req.GrantType, wantGrantType)
	}

	if req.ClientID != "device-client" {
		t.Errorf("got ClientID %q, want %q", req.ClientID, "device-client")
	}

	if req.ClientSecret != "device-secret" {
		t.Errorf("got ClientSecret %q, want %q", req.ClientSecret, "device-secret")
	}

	if req.AuthMethod != AuthMethodBasic {
		t.Errorf("got AuthMethod %v, want %v", req.AuthMethod, AuthMethodBasic)
	}

	// Check device_code param
	gotDeviceCode := req.Params.Get("device_code")
	if gotDeviceCode != "device123" {
		t.Errorf("got device_code %q, want %q", gotDeviceCode, "device123")
	}
}

func TestParseTokenResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantErrMsg string
		wantData   map[string]interface{}
	}{
		{
			name:       "successful response",
			statusCode: 200,
			body:       `{"access_token":"token123","token_type":"Bearer","expires_in":3600}`,
			wantErr:    false,
			wantData: map[string]interface{}{
				"access_token": "token123",
				"token_type":   "Bearer",
				"expires_in":   float64(3600),
			},
		},
		{
			name:       "oauth2 error response",
			statusCode: 400,
			body:       `{"error":"invalid_request","error_description":"Missing required parameter"}`,
			wantErr:    true,
			wantErrMsg: "oauth protocol error",
		},
		{
			name:       "http error without oauth2 format",
			statusCode: 500,
			body:       `{"message":"Internal server error"}`,
			wantErr:    true,
			wantErrMsg: "oauth http failure",
		},
		{
			name:       "invalid json",
			statusCode: 200,
			body:       `invalid json`,
			wantErr:    true,
			wantErrMsg: "json parsing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				StatusCode: tt.statusCode,
				Body:       []byte(tt.body),
			}

			data, err := ParseTokenResponse(resp)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}

				for key, want := range tt.wantData {
					got := data[key]
					if got != want {
						t.Errorf("got %s=%v, want %v", key, got, want)
					}
				}
			}
		})
	}
}
