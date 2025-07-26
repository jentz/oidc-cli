package httpclient

import (
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/webflow"
)

func TestDefaultResponseValidator_ValidateResponse(t *testing.T) {
	validator := &DefaultResponseValidator{}

	tests := []struct {
		name        string
		req         *AuthorizationCodeRequest
		resp        *webflow.CallbackResponse
		want        *AuthorizationCodeResponse
		wantErr     bool
		errContains string
	}{
		{
			name: "successful response with state",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    "test-state",
			},
			resp: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "test-state",
			},
			want: &AuthorizationCodeResponse{
				Code:  "auth-code-123",
				State: "test-state",
			},
			wantErr: false,
		},
		{
			name: "successful response without state",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
			},
			resp: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "some-state",
			},
			want: &AuthorizationCodeResponse{
				Code:  "auth-code-123",
				State: "",
			},
			wantErr: false,
		},
		{
			name: "state mismatch",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    "expected-state",
			},
			resp: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "different-state",
			},
			wantErr:     true,
			errContains: "state mismatch: expected \"expected-state\" but got \"different-state\"",
		},
		{
			name: "missing authorization code",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    "test-state",
			},
			resp: &webflow.CallbackResponse{
				State:            "test-state",
				ErrorMsg:         "access_denied",
				ErrorDescription: "User denied the request",
			},
			wantErr:     true,
			errContains: "authorization failed with error access_denied and description User denied the request",
		},
		{
			name: "missing authorization code with empty error",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
			},
			resp: &webflow.CallbackResponse{
				// No code, no error details
			},
			wantErr:     true,
			errContains: "authorization failed with error  and description ",
		},
		{
			name:        "nil request",
			req:         nil,
			resp:        &webflow.CallbackResponse{Code: "test-code"},
			wantErr:     true,
			errContains: "request cannot be nil",
		},
		{
			name: "nil response",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
			},
			resp:        nil,
			wantErr:     true,
			errContains: "response cannot be nil",
		},
		{
			name: "empty state in request allows any callback state",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    "",
			},
			resp: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "any-state",
			},
			want: &AuthorizationCodeResponse{
				Code:  "auth-code-123",
				State: "",
			},
			wantErr: false,
		},
		{
			name: "both states empty",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				State:    "",
			},
			resp: &webflow.CallbackResponse{
				Code:  "auth-code-123",
				State: "",
			},
			want: &AuthorizationCodeResponse{
				Code:  "auth-code-123",
				State: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validator.ValidateResponse(tt.req, tt.resp)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateResponse() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateResponse() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got == nil {
				t.Error("ValidateResponse() returned nil result")
				return
			}

			if got.Code != tt.want.Code {
				t.Errorf("ValidateResponse() Code = %v, want %v", got.Code, tt.want.Code)
			}

			if got.State != tt.want.State {
				t.Errorf("ValidateResponse() State = %v, want %v", got.State, tt.want.State)
			}
		})
	}
}

func TestDefaultResponseValidator_Interface(_ *testing.T) {
	var _ ResponseValidator = (*DefaultResponseValidator)(nil)
}
