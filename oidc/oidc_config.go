package oidc

import (
	"context"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

type Config struct {
	ClientID                           string
	ClientSecret                       string
	IssuerURL                          string
	DiscoveryEndpoint                  string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	DeviceAuthorizationEndpoint        string
	IntrospectionEndpoint              string
	UserinfoEndpoint                   string
	JWKSEndpoint                       string
	SkipTLSVerify                      bool
	AuthMethod                         httpclient.AuthMethod
	DPoPPrivateKeyFile                 string
	DPoPPublicKeyFile                  string
	DPoPKeys                           DPoPKeys
	Client                             *httpclient.Client
	Logger                             *log.Logger
}

// NewConfig returns a Config with sensible defaults. Logger is set to
// log.Discard() so callers that don't need logging can skip setting it.
func NewConfig() *Config {
	return &Config{
		Logger: log.Discard(),
	}
}

func (c *Config) DiscoverEndpoints(ctx context.Context) error {
	client := c.Client

	discoveryConfig, err := c.Discover(ctx, client)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	// Set endpoints from discovery config if not already set by user
	if c.AuthorizationEndpoint == "" {
		c.AuthorizationEndpoint = discoveryConfig.AuthorizationEndpoint
	}

	if c.PushedAuthorizationRequestEndpoint == "" {
		c.PushedAuthorizationRequestEndpoint = discoveryConfig.PushedAuthorizationRequestEndpoint
	}

	if c.TokenEndpoint == "" {
		c.TokenEndpoint = discoveryConfig.TokenEndpoint
	}

	if c.DeviceAuthorizationEndpoint == "" {
		c.DeviceAuthorizationEndpoint = discoveryConfig.DeviceAuthorizationEndpoint
	}

	if c.IntrospectionEndpoint == "" {
		c.IntrospectionEndpoint = discoveryConfig.IntrospectionEndpoint
	}

	if c.UserinfoEndpoint == "" {
		c.UserinfoEndpoint = discoveryConfig.UserinfoEndpoint
	}

	if c.JWKSEndpoint == "" {
		c.JWKSEndpoint = discoveryConfig.JwksURI
	}

	// set default auth method if not set by user
	if c.AuthMethod == "" {
		for _, method := range discoveryConfig.TokenEndpointAuthMethods {
			authMethodValue := httpclient.AuthMethod(method)
			if authMethodValue.IsValid() {
				c.AuthMethod = authMethodValue
				break
			}
		}
	}

	return nil
}

func (c *Config) ReadKeyFiles() error {
	// Parse the private key if provided
	if c.DPoPPrivateKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.DPoPPrivateKeyFile)
		if err != nil {
			return fmt.Errorf("could not read private key file: %w", err)
		}
		c.DPoPKeys.Private, err = crypto.ParsePrivateKeyPEMBlock(pem)
		if err != nil {
			return fmt.Errorf("could not parse private key: %w", err)
		}
	}

	// Parse the public key if provided
	if c.DPoPPublicKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.DPoPPublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}
		c.DPoPKeys.Public, err = crypto.ParsePublicKeyPEMBlock(pem)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}
	return nil
}

// setupPKCE generates a PKCE code verifier when enabled, returning an empty
// verifier when not. A client with no secret cannot authenticate at the token
// endpoint, so PKCE secures a public client and the auth method falls back to
// none.
func (c *Config) setupPKCE(enabled bool) (string, error) {
	if !enabled {
		return "", nil
	}
	if c.ClientSecret == "" {
		c.AuthMethod = httpclient.AuthMethodNone
	}
	codeVerifier, err := crypto.GeneratePKCECodeVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	return codeVerifier, nil
}
