package httpclient

import (
	"errors"
	"testing"
)

// MockBrowser is a mock implementation of webflow.Browser for testing.
type MockBrowser struct {
	openFunc func(url string) error
}

func (m *MockBrowser) Open(url string) error {
	if m.openFunc != nil {
		return m.openFunc(url)
	}
	return nil
}

func TestDefaultBrowserLauncher_OpenURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		mockOpen   func(url string) error
		wantErr    bool
		errMessage string
	}{
		{
			name: "successful open",
			url:  "https://example.com",
			mockOpen: func(url string) error {
				if url != "https://example.com" {
					t.Errorf("Expected URL https://example.com, got %s", url)
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "browser error",
			url:  "https://example.com",
			mockOpen: func(_ string) error {
				return errors.New("browser failed")
			},
			wantErr:    true,
			errMessage: "browser failed",
		},
		{
			name: "empty URL",
			url:  "",
			mockOpen: func(url string) error {
				if url != "" {
					t.Errorf("Expected empty URL, got %s", url)
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBrowser := &MockBrowser{openFunc: tt.mockOpen}
			launcher := NewDefaultBrowserLauncherWithBrowser(mockBrowser)

			err := launcher.OpenURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Errorf("OpenURL() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errMessage != "" && err.Error() != tt.errMessage {
					t.Errorf("OpenURL() error = %v, want %v", err.Error(), tt.errMessage)
				}
				return
			}

			if err != nil {
				t.Errorf("OpenURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultBrowserLauncher_Interface(_ *testing.T) {
	var _ BrowserLauncher = (*DefaultBrowserLauncher)(nil)
}

func TestNewDefaultBrowserLauncher(t *testing.T) {
	launcher := NewDefaultBrowserLauncher()
	if launcher == nil {
		t.Error("NewDefaultBrowserLauncher() returned nil")
		return
	}
	if launcher.browser == nil {
		t.Error("NewDefaultBrowserLauncher() browser is nil")
	}
}

func TestNewDefaultBrowserLauncherWithBrowser(t *testing.T) {
	mockBrowser := &MockBrowser{}
	launcher := NewDefaultBrowserLauncherWithBrowser(mockBrowser)

	if launcher == nil {
		t.Error("NewDefaultBrowserLauncherWithBrowser() returned nil")
		return
	}
	if launcher.browser != mockBrowser {
		t.Error("NewDefaultBrowserLauncherWithBrowser() did not set the provided browser")
	}
}
