package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExecutePushedAuthorizationRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		req        *PushedAuthorizationRequest
		wantParams map[string]string
		wantAuth   string
	}{
		{
			name: "basic auth method",
			req: &PushedAuthorizationRequest{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthMethod:   AuthMethodBasic,
				Params: &url.Values{
					"response_type": []string{"code"},
					"scope":         []string{"openid profile"},
				},
			},
			wantParams: map[string]string{
				"response_type": "code",
				"scope":         "openid profile",
			},
			wantAuth: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=", // base64 of test-client:test-secret
		},
		{
			name: "post auth method",
			req: &PushedAuthorizationRequest{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthMethod:   AuthMethodPost,
				Params: &url.Values{
					"response_type": []string{"code"},
					"scope":         []string{"openid"},
				},
			},
			wantParams: map[string]string{
				"response_type": "code",
				"scope":         "openid",
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		},
		{
			name: "post auth method without client secret",
			req: &PushedAuthorizationRequest{
				ClientID:     "public-client",
				ClientSecret: "", // No secret for public client
				AuthMethod:   AuthMethodPost,
				Params: &url.Values{
					"response_type": []string{"code"},
					"scope":         []string{"openid"},
				},
			},
			wantParams: map[string]string{
				"response_type": "code",
				"scope":         "openid",
				"client_id":     "public-client",
				// client_secret should not be set
			},
		},
		{
			name: "none auth method",
			req: &PushedAuthorizationRequest{
				ClientID:   "public-client",
				AuthMethod: AuthMethodNone,
				Params: &url.Values{
					"response_type": []string{"code"},
					"scope":         []string{"openid email"},
				},
			},
			wantParams: map[string]string{
				"response_type": "code",
				"scope":         "openid email",
				"client_id":     "public-client",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST method, got %s", r.Method)
				}

				// Check Content-Type header for form data
				contentType := r.Header.Get("Content-Type")
				if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
					t.Errorf("Expected form content type, got %s", contentType)
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

				// For POST auth method without secret, ensure client_secret is not set when empty
				if tt.req.AuthMethod == AuthMethodPost && tt.req.ClientSecret == "" {
					if r.FormValue("client_secret") != "" {
						t.Error("client_secret should not be set when empty")
					}
				}

				// Return a successful PAR response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:example","expires_in":90}`))
			}))
			defer ts.Close()

			client := NewClient(nil)
			resp, err := client.ExecutePushedAuthorizationRequest(context.Background(), ts.URL, tt.req)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("Expected status 201, got %d", resp.StatusCode)
			}
		})
	}
}

func TestParsePushedAuthorizationResponse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantErrMsg string
		wantData   *PushedAuthorizationResponse
	}{
		{
			name:       "successful response",
			statusCode: 201,
			body:       `{"request_uri":"urn:ietf:params:oauth:request_uri:example","expires_in":90}`,
			wantErr:    false,
			wantData: &PushedAuthorizationResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:example",
				ExpiresIn:  90,
			},
		},
		{
			name:       "successful response with different expires_in",
			statusCode: 201,
			body:       `{"request_uri":"urn:ietf:params:oauth:request_uri:another","expires_in":300}`,
			wantErr:    false,
			wantData: &PushedAuthorizationResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:another",
				ExpiresIn:  300,
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
			name:       "oauth2 error without description",
			statusCode: 400,
			body:       `{"error":"invalid_client"}`,
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
			name:       "invalid json in error response",
			statusCode: 400,
			body:       `invalid json`,
			wantErr:    true,
			wantErrMsg: "json parsing error",
		},
		{
			name:       "invalid json in success response",
			statusCode: 201,
			body:       `invalid json`,
			wantErr:    true,
			wantErrMsg: "json parsing error",
		},
		{
			name:       "malformed success response",
			statusCode: 201,
			body:       `{"request_uri":"urn:example","expires_in":"invalid"}`,
			wantErr:    true,
			wantErrMsg: "json parsing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := &Response{
				StatusCode: tt.statusCode,
				Body:       []byte(tt.body),
			}

			parResp, err := ParsePushedAuthorizationResponse(resp)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if parResp == nil {
				t.Error("Expected non-nil response, got nil")
				return
			}

			if parResp.RequestURI != tt.wantData.RequestURI {
				t.Errorf("got RequestURI %q, want %q", parResp.RequestURI, tt.wantData.RequestURI)
			}

			if parResp.ExpiresIn != tt.wantData.ExpiresIn {
				t.Errorf("got ExpiresIn %d, want %d", parResp.ExpiresIn, tt.wantData.ExpiresIn)
			}
		})
	}
}

func TestPushedAuthorizationRequest_Integration(t *testing.T) {
	t.Parallel()
	// Integration test that combines ExecutePushedAuthorizationRequest and ParsePushedAuthorizationResponse
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		// When using AuthMethodBasic, client_id should NOT be in the form - it's in the Authorization header
		// Validate the Authorization header instead
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Missing authorization"}`))
			return
		}

		// Validate required form parameters
		if r.FormValue("response_type") != "code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Invalid response_type"}`))
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:integration","expires_in":120}`))
	}))
	defer ts.Close()

	client := NewClient(nil)

	req := &PushedAuthorizationRequest{
		ClientID:     "integration-client",
		ClientSecret: "integration-secret",
		AuthMethod:   AuthMethodBasic,
		Params: &url.Values{
			"response_type": []string{"code"},
			"scope":         []string{"openid profile"},
			"redirect_uri":  []string{"https://example.com/callback"},
		},
	}

	// Execute the PAR request
	resp, err := client.ExecutePushedAuthorizationRequest(context.Background(), ts.URL, req)
	if err != nil {
		t.Fatalf("Failed to execute PAR request: %v", err)
	}

	// Parse the response
	parResp, err := ParsePushedAuthorizationResponse(resp)
	if err != nil {
		t.Fatalf("Failed to parse PAR response: %v", err)
	}

	// Verify the response
	wantRequestURI := "urn:ietf:params:oauth:request_uri:integration"
	if parResp.RequestURI != wantRequestURI {
		t.Errorf("got RequestURI %q, want %q", parResp.RequestURI, wantRequestURI)
	}

	wantExpiresIn := 120
	if parResp.ExpiresIn != wantExpiresIn {
		t.Errorf("got ExpiresIn %d, want %d", parResp.ExpiresIn, wantExpiresIn)
	}
}
