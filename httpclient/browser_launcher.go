package httpclient

import (
	"github.com/jentz/oidc-cli/webflow"
)

// DefaultBrowserLauncher implements BrowserLauncher using the webflow.Browser.
type DefaultBrowserLauncher struct {
	browser webflow.Browser
}

// Ensure DefaultBrowserLauncher implements the interface.
var _ BrowserLauncher = (*DefaultBrowserLauncher)(nil)

// NewDefaultBrowserLauncher creates a new DefaultBrowserLauncher with the default browser.
func NewDefaultBrowserLauncher() *DefaultBrowserLauncher {
	return &DefaultBrowserLauncher{
		browser: webflow.NewBrowser(),
	}
}

// NewDefaultBrowserLauncherWithBrowser creates a new DefaultBrowserLauncher with a custom browser.
// This is useful for testing with mock browsers.
func NewDefaultBrowserLauncherWithBrowser(browser webflow.Browser) *DefaultBrowserLauncher {
	return &DefaultBrowserLauncher{
		browser: browser,
	}
}

// OpenURL opens the specified URL in the system's default browser.
func (b *DefaultBrowserLauncher) OpenURL(url string) error {
	return b.browser.Open(url)
}
