package oidc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/jentz/oidc-cli/httpclient"
)

type mockTransport func(req *http.Request) (*http.Response, error)

func (f mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

const defaultBody = `{
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "jwks_uri": "https://example.com/jwks"
}`

func TestClientDiscover(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   *Config
		response *http.Response
		want     *DiscoveryConfiguration
		wantErr  bool
		wantURL  string
	}{
		{
			name: "successful discovery",
			config: &Config{
				IssuerURL: "https://example.com",
			},
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(defaultBody)),
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "custom discovery endpoint",
			config: &Config{
				IssuerURL:         "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/custom",
			},
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(defaultBody)),
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantURL: "https://example.com/.well-known/custom",
		},
		{
			name: "invalid issuer",
			config: &Config{
				IssuerURL: "https://example.com",
			},
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"issuer": "https://invalid.com"}`)),
			},
			wantErr: true,
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "http error",
			config: &Config{
				IssuerURL: "https://example.com",
			},
			response: &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString("not found")),
			},
			wantErr: true,
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var capturedRequest *http.Request
			transport := mockTransport(func(req *http.Request) (*http.Response, error) {
				capturedRequest = req
				return tt.response, nil
			})

			client := httpclient.NewClient(
				&httpclient.Config{
					Transport: transport,
				})

			got, err := tt.config.Discover(context.Background(), client)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Discover() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.Discover() = %v, want %v", got, tt.want)
			}

			if capturedRequest.URL.String() != tt.wantURL {
				t.Errorf("Client.Discover() URL = %v, want %v", capturedRequest.URL.String(), tt.wantURL)
			}
		})
	}
}
