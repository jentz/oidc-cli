package oidc

import (
	"context"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

// Config composes the three concerns a flow runs against: the OIDC protocol
// settings, the runtime dependencies, and the DPoP keypair.
type Config struct {
	OIDC     OIDCConfig
	Runtime  Runtime
	DPoPKeys DPoPKeys
}

// OIDCConfig holds the OIDC protocol settings: client credentials, the client
// authentication method, the issuer, and the endpoints. It owns the mutations
// that complete itself: discovery resolution, the auth-method default, and the
// public-client fallback to no authentication.
type OIDCConfig struct {
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
	AuthMethod                         httpclient.AuthMethod
}

// Runtime holds the dependencies a flow executes against rather than any
// protocol setting: the HTTP client and the logger.
type Runtime struct {
	Client *httpclient.Client
	Logger *log.Logger
}

// NewConfig returns a Config with sensible defaults. The logger is set to
// log.Discard() so callers that don't need logging can skip setting it.
func NewConfig() *Config {
	return &Config{
		Runtime: Runtime{Logger: log.Discard()},
	}
}

// DiscoverEndpoints fills in every endpoint the user did not set from the
// provider's discovery document, then picks a default auth method when none was
// chosen. The client is borrowed from the runtime to make the request;
// OIDCConfig holds no client of its own.
func (o *OIDCConfig) DiscoverEndpoints(ctx context.Context, client *httpclient.Client) error {
	discoveryConfig, err := o.Discover(ctx, client)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	// Set endpoints from discovery config if not already set by user
	if o.AuthorizationEndpoint == "" {
		o.AuthorizationEndpoint = discoveryConfig.AuthorizationEndpoint
	}

	if o.PushedAuthorizationRequestEndpoint == "" {
		o.PushedAuthorizationRequestEndpoint = discoveryConfig.PushedAuthorizationRequestEndpoint
	}

	if o.TokenEndpoint == "" {
		o.TokenEndpoint = discoveryConfig.TokenEndpoint
	}

	if o.DeviceAuthorizationEndpoint == "" {
		o.DeviceAuthorizationEndpoint = discoveryConfig.DeviceAuthorizationEndpoint
	}

	if o.IntrospectionEndpoint == "" {
		o.IntrospectionEndpoint = discoveryConfig.IntrospectionEndpoint
	}

	if o.UserinfoEndpoint == "" {
		o.UserinfoEndpoint = discoveryConfig.UserinfoEndpoint
	}

	if o.JWKSEndpoint == "" {
		o.JWKSEndpoint = discoveryConfig.JwksURI
	}

	// set default auth method if not set by user
	if o.AuthMethod == "" {
		for _, method := range discoveryConfig.TokenEndpointAuthMethods {
			authMethodValue := httpclient.AuthMethod(method)
			if authMethodValue.IsValid() {
				o.AuthMethod = authMethodValue
				break
			}
		}
	}

	return nil
}

// setupPKCE generates a PKCE code verifier when enabled, returning an empty
// verifier when not. A client with no secret cannot authenticate at the token
// endpoint, so PKCE secures a public client and the auth method falls back to
// none.
func (o *OIDCConfig) setupPKCE(enabled bool) (string, error) { //nolint:revive // flag-parameter: PKCE is an optional per-flow toggle, so a bool cleanly gates verifier generation.
	if !enabled {
		return "", nil
	}
	codeVerifier, err := crypto.GeneratePKCECodeVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	// Flip the auth method only after the fallible step, so a failed generation
	// leaves the config untouched.
	if o.ClientSecret == "" {
		o.AuthMethod = httpclient.AuthMethodNone
	}
	return codeVerifier, nil
}
