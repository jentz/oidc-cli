package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteDeviceAuthorizationRequest(t *testing.T) {
	tests := []struct {
		name       string
		req        *DeviceAuthorizationRequest
		resp       *Response
		wantStatus int
	}{
		{
			name: "successful device authorization",
			req: &DeviceAuthorizationRequest{
				ClientID: "test-client-id",
				Scope:    "openid profile email",
			},
			resp: &Response{
				StatusCode: http.StatusOK,
				Body: []byte(`{
					"device_code": "test-device-code",
					"user_code": "test-user-code",
					"verification_uri": "https://example.com/verify",
					"verification_uri_complete": "https://example.com/verify?user_code=test-user-code",
					"expires_in": 600,
					"interval": 5
				}`),
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "server error",
			req: &DeviceAuthorizationRequest{
				ClientID: "test-client-id",
				Scope:    "openid",
			},
			resp: &Response{
				StatusCode: http.StatusInternalServerError,
				Body:       []byte(`{"error":"server_error","error_description":"Internal server error"}`),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "unauthorized client",
			req: &DeviceAuthorizationRequest{
				ClientID: "invalid-client",
				Scope:    "openid",
			},
			resp: &Response{
				StatusCode: http.StatusUnauthorized,
				Body:       []byte(`{"error":"unauthorized_client","error_description":"Client is not authorized"}`),
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}

				if err := r.ParseForm(); err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}

				if got := r.FormValue("client_id"); got != tt.req.ClientID {
					t.Errorf("client_id = %v, want %v", got, tt.req.ClientID)
				}

				if got := r.FormValue("scope"); got != tt.req.Scope {
					t.Errorf("scope = %v, want %v", got, tt.req.Scope)
				}

				w.WriteHeader(tt.resp.StatusCode)
				_, err := w.Write(tt.resp.Body)
				if err != nil {
					t.Fatalf("failed to write response body: %v", err)
				}
			}))
			defer ts.Close()

			client := NewClient(nil)
			resp, err := client.ExecuteDeviceAuthorizationRequest(context.Background(), ts.URL, tt.req, nil)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestParseDeviceAuthorizationResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantErrMsg string
		wantData   *DeviceAuthorizationResponse
	}{
		{
			name:       "successful response",
			statusCode: 200,
			body: `{"device_code": "test-device-code",
					"user_code": "test-user-code",
					"verification_uri": "https://example.com/verify",
					"verification_uri_complete": "https://example.com/verify?user_code=test-user-code",
					"expires_in": 600,
					"interval": 5
					}`,
			wantErr: false,
			wantData: &DeviceAuthorizationResponse{
				DeviceCode:              "test-device-code",
				UserCode:                "test-user-code",
				VerificationURI:         "https://example.com/verify",
				VerificationURIComplete: "https://example.com/verify?user_code=test-user-code",
				ExpiresIn:               600,
				Interval:                5,
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

			deviceAuthResp, err := ParseDeviceAuthorizationResponse(resp)

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

			if deviceAuthResp == nil {
				t.Error("Expected non-nil response, got nil")
				return
			}

			if deviceAuthResp.DeviceCode != tt.wantData.DeviceCode {
				t.Errorf("DeviceCode = %v, want %v", deviceAuthResp.DeviceCode, tt.wantData.DeviceCode)
			}
			if deviceAuthResp.UserCode != tt.wantData.UserCode {
				t.Errorf("UserCode = %v, want %v", deviceAuthResp.UserCode, tt.wantData.UserCode)
			}
			if deviceAuthResp.VerificationURI != tt.wantData.VerificationURI {
				t.Errorf("VerificationURI = %v, want %v", deviceAuthResp.VerificationURI, tt.wantData.VerificationURI)
			}
			if deviceAuthResp.VerificationURIComplete != tt.wantData.VerificationURIComplete {
				t.Errorf("VerificationURIComplete = %v, want %v", deviceAuthResp.VerificationURIComplete, tt.wantData.VerificationURIComplete)
			}
			if deviceAuthResp.ExpiresIn != tt.wantData.ExpiresIn {
				t.Errorf("ExpiresIn = %v, want %v", deviceAuthResp.ExpiresIn, tt.wantData.ExpiresIn)
			}
			if deviceAuthResp.Interval != tt.wantData.Interval {
				t.Errorf("Interval = %v, want %v", deviceAuthResp.Interval, tt.wantData.Interval)
			}
		})
	}
}
