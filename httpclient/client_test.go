package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Since we can't directly check internal fields without exposing them,
	// we'll test behavior instead using a mock server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("test response"))
	}))
	defer ts.Close()

	tests := []struct {
		name           string
		cfg            *Config
		expectTimeout  bool // We'll test timeout behavior
		timeoutSeconds int  // How long to sleep on the server side
	}{
		{
			name:           "nil config uses defaults",
			cfg:            nil,
			expectTimeout:  false,
			timeoutSeconds: 1,
		},
		{
			name: "custom timeout works",
			cfg: &Config{
				Timeout: 5 * time.Second,
			},
			expectTimeout:  false,
			timeoutSeconds: 3,
		},
		{
			name: "timeout works correctly",
			cfg: &Config{
				Timeout: 1 * time.Second,
			},
			expectTimeout:  true,
			timeoutSeconds: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that sleeps for the specified time
			sleepServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(time.Duration(tt.timeoutSeconds) * time.Second)
				_, _ = w.Write([]byte("response after delay"))
			}))
			defer sleepServer.Close()

			client := NewClient(tt.cfg)
			ctx := context.Background()

			// Test whether the request times out as expected
			_, err := client.Get(ctx, sleepServer.URL, nil)

			if tt.expectTimeout && err == nil {
				t.Errorf("Expected timeout error but got none")
			}
			if !tt.expectTimeout && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestTLSSkipVerify(t *testing.T) {
	// Create a server with a self-signed cert
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure response"))
	}))
	defer ts.Close()

	t.Run("Skips TLS verification when configured", func(t *testing.T) {
		client := NewClient(&Config{SkipTLSVerify: true})
		_, err := client.Get(context.Background(), ts.URL, nil)
		if err != nil {
			t.Errorf("Expected no error with SkipTLSVerify but got: %v", err)
		}
	})

	t.Run("Fails on invalid cert by default", func(t *testing.T) {
		client := NewClient(nil) // Default config
		_, err := client.Get(context.Background(), ts.URL, nil)
		if err == nil {
			t.Errorf("Expected TLS verification error but got none")
		}
	})
}

func TestCustomTransport(t *testing.T) {
	// Test that a custom is transport respected
	customTransport := &http.Transport{
		MaxIdleConns: 100,
	}

	cfg := &Config{
		Transport: customTransport,
	}

	// Create a mock server that checks the User-Agent
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("test response"))
	}))
	defer ts.Close()

	client := NewClient(cfg)
	resp, err := client.Get(context.Background(), ts.URL, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsSuccess() {
		t.Errorf("Expected successful response, got: %d", resp.StatusCode)
	}
}

func TestPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("received: " + string(body)))
	}))
	defer ts.Close()

	client := NewClient(nil)
	body := strings.NewReader("test data")
	headers := map[string]string{"Custom-Header": "test-value"}

	resp, err := client.Post(context.Background(), ts.URL, body, headers)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got := resp.StatusCode
	want := http.StatusCreated
	if got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}

	gotBody := resp.String()
	wantBody := "received: test data"
	if gotBody != wantBody {
		t.Errorf("got body %q, want %q", gotBody, wantBody)
	}
}

func TestPostForm(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Expected form content type, got %s", contentType)
		}

		_ = r.ParseForm()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("username=" + r.FormValue("username")))
	}))
	defer ts.Close()

	client := NewClient(nil)
	formValues := url.Values{
		"username": []string{"testuser"},
		"password": []string{"secret"},
	}
	headers := map[string]string{"Custom-Header": "form-test"}

	resp, err := client.PostForm(context.Background(), ts.URL, formValues, headers)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got := resp.StatusCode
	want := http.StatusOK
	if got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}

	gotBody := resp.String()
	wantBody := "username=testuser"
	if gotBody != wantBody {
		t.Errorf("got body %q, want %q", gotBody, wantBody)
	}
}

func TestPostJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected JSON content type, got %s", contentType)
		}

		var data map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&data)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"received": data["message"],
			"status":   "ok",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer ts.Close()

	client := NewClient(nil)
	requestData := map[string]interface{}{
		"message": "hello world",
		"count":   42,
	}
	headers := map[string]string{"Custom-Header": "json-test"}

	resp, err := client.PostJSON(context.Background(), ts.URL, requestData, headers)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got := resp.StatusCode
	want := http.StatusOK
	if got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}

	var responseData map[string]interface{}
	err = resp.JSON(&responseData)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	gotMessage := responseData["received"].(string)
	wantMessage := "hello world"
	if gotMessage != wantMessage {
		t.Errorf("got message %q, want %q", gotMessage, wantMessage)
	}
}

func TestPostJSON_MarshalError(t *testing.T) {
	client := NewClient(nil)

	// Use a function as data, which cannot be marshaled to JSON
	invalidData := func() {}

	_, err := client.PostJSON(context.Background(), "http://example.com", invalidData, nil)
	if err == nil {
		t.Error("Expected JSON marshal error, got nil")
	}
}

func TestResponseMethods(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"message": "test response",
			"code":    200,
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer ts.Close()

	client := NewClient(nil)
	resp, err := client.Get(context.Background(), ts.URL, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Test String method
	gotString := resp.String()
	if !strings.Contains(gotString, "test response") {
		t.Errorf("String() method should contain 'test response', got %q", gotString)
	}

	// Test JSON method
	var data map[string]interface{}
	err = resp.JSON(&data)
	if err != nil {
		t.Fatalf("JSON() method failed: %v", err)
	}

	gotMessage := data["message"].(string)
	wantMessage := "test response"
	if gotMessage != wantMessage {
		t.Errorf("got message %q, want %q", gotMessage, wantMessage)
	}

	gotCode := int(data["code"].(float64))
	wantCode := 200
	if gotCode != wantCode {
		t.Errorf("got code %d, want %d", gotCode, wantCode)
	}
}

func TestResponseJSON_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(nil)
	resp, err := client.Get(context.Background(), ts.URL, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var data map[string]interface{}
	err = resp.JSON(&data)
	if err == nil {
		t.Error("Expected JSON unmarshal error, got nil")
	}
}

func TestResponseIsSuccess(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"200 OK", 200, true},
		{"201 Created", 201, true},
		{"299 edge case", 299, true},
		{"300 Redirect", 300, false},
		{"404 Not Found", 404, false},
		{"500 Server Error", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte("test"))
			}))
			defer ts.Close()

			client := NewClient(nil)
			resp, err := client.Get(context.Background(), ts.URL, nil)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			got := resp.IsSuccess()
			if got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v for status code %d (actual status: %d)", got, tt.want, tt.statusCode, resp.StatusCode)
			}
		})
	}
}

func TestDo_InvalidURL(t *testing.T) {
	client := NewClient(nil)
	_, err := client.Do(context.Background(), http.MethodGet, "://invalid-url", nil, nil)
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestDo_ContextCanceled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("delayed response"))
	}))
	defer ts.Close()

	client := NewClient(&Config{Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context immediately
	cancel()

	_, err := client.Do(ctx, http.MethodGet, ts.URL, nil, nil)
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

// Test that verifies response body close error propagation works correctly
func TestDo_ResponseBodyCloseError(t *testing.T) {
	// Create a test server that returns a response with a body that fails to close
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test response"))
	}))
	defer ts.Close()

	// Create a custom transport that returns a response with a body that fails to close
	client := NewClient(&Config{
		Transport: &failingBodyCloseTransport{},
	})

	_, err := client.Do(context.Background(), http.MethodGet, ts.URL, nil, nil)
	
	// Verify that the close error is properly propagated
	if err == nil {
		t.Error("Expected error from failing to close response body, but got nil")
	} else if !strings.Contains(err.Error(), "error closing response body") {
		t.Errorf("Expected error about closing response body, got: %v", err)
	}
}

// failingBodyCloseTransport is a custom transport that returns responses with bodies that fail to close
type failingBodyCloseTransport struct{}

func (t *failingBodyCloseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a response with a failing body closer
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       &failingCloseReadCloser{data: []byte("test response")},
		Request:    req,
	}
	return resp, nil
}

// failingCloseReadCloser implements io.ReadCloser but Close() always returns an error
type failingCloseReadCloser struct {
	data   []byte
	offset int
}

func (f *failingCloseReadCloser) Read(p []byte) (n int, err error) {
	if f.offset >= len(f.data) {
		return 0, io.EOF
	}
	n = copy(p, f.data[f.offset:])
	f.offset += n
	return n, nil
}

func (f *failingCloseReadCloser) Close() error {
	return fmt.Errorf("simulated close error")
}
