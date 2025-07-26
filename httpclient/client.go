package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds HTTP client configuration.
type Config struct {
	SkipTLSVerify bool              // Skip TLS verification for HTTP requests
	Timeout       time.Duration     // Timeout for HTTP requests
	Transport     http.RoundTripper // Custom HTTP transport, if any
}

// Client is a wrapper around http.Client with utility methods
type Client struct {
	client   *http.Client
	authDeps *AuthFlowDependencies // Optional dependencies for authorization flows
}

// Response represents an HTTP response with convenience methods
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// NewClient creates a configured HTTP client
func NewClient(cfg *Config) *Client {
	if cfg == nil {
		cfg = &Config{
			Timeout: 10 * time.Second,
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipTLSVerify,
			},
		}
	}

	return &Client{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		authDeps: NewAuthFlowDependencies(), // Initialize with default dependencies
	}
}

// SetAuthFlowDependencies sets custom dependencies for authorization flows.
// This is primarily used for testing with mock implementations.
func (c *Client) SetAuthFlowDependencies(deps *AuthFlowDependencies) {
	if deps != nil {
		c.authDeps = deps
	}
}

// Do performs an HTTP request and handles response processing
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (resp *Response, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	httpResp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer func() {
		closeErr := httpResp.Body.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("error closing response body: %w", closeErr)
		}
	}()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	return &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       respBody,
	}, err
}

// Get performs an HTTP GET request
func (c *Client) Get(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, url, nil, headers)
}

// Post performs an HTTP POST request
func (c *Client) Post(ctx context.Context, url string, body io.Reader, headers map[string]string) (*Response, error) {
	return c.Do(ctx, http.MethodPost, url, body, headers)
}

// PostForm sends a form-encoded POST request
func (c *Client) PostForm(ctx context.Context, url string, formValues url.Values, headers map[string]string) (*Response, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"

	return c.Post(ctx, url, strings.NewReader(formValues.Encode()), headers)
}

// PostJSON sends a JSON POST request
func (c *Client) PostJSON(ctx context.Context, url string, data interface{}, headers map[string]string) (*Response, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/json"

	return c.Post(ctx, url, bytes.NewReader(jsonData), headers)
}

// JSON unmarshals the response body into the provided value
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal(r.Body, v)
}

// String returns the response body as a string
func (r *Response) String() string {
	return string(r.Body)
}

// IsSuccess returns true if the response status code is in the 2xx range
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}
