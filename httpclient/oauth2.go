package httpclient

import (
	"fmt"
	"strings"
)

// CustomArgs represents additional parameters that can be included in OAuth2 requests
type CustomArgs map[string]string

// Set sets a custom argument arg must be a key-value pair in the format "key=value".
func (c *CustomArgs) Set(arg string) error {
	k, v, ok := strings.Cut(arg, "=")
	if !ok {
		return fmt.Errorf("invalid custom argument %q, must be in the format key=value", arg)
	}
	(*c)[k] = v
	return nil
}

// AuthMethod represents OAuth2 client authentication methods
type AuthMethod string

const (
	// AuthMethodBasic uses HTTP Basic Auth
	AuthMethodBasic AuthMethod = "client_secret_basic"
	// AuthMethodPost includes client credentials in the request body
	AuthMethodPost AuthMethod = "client_secret_post"
	// AuthMethodNone doesn't include client authentication
	AuthMethodNone AuthMethod = "none"
)

var validAuthMethods = map[AuthMethod]bool{
	AuthMethodBasic: true,
	AuthMethodPost:  true,
	AuthMethodNone:  true,
}

// IsValid checks if the AuthMethod is valid
func (a *AuthMethod) IsValid() bool {
	return validAuthMethods[*a]
}

func (a *AuthMethod) String() string {
	return string(*a)
}

// Set sets the AuthMethod from a string value
func (a *AuthMethod) Set(value string) error {
	method := AuthMethod(value)
	if !method.IsValid() {
		return fmt.Errorf("invalid auth method %q, valid values are: %s, %s, %s",
			value, AuthMethodBasic, AuthMethodPost, AuthMethodNone)
	}
	*a = method
	return nil
}
