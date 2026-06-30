package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jentz/oidc-cli/httpclient"
)

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type DiscoveryConfiguration struct {
	Issuer                             string   `json:"issuer,omitempty"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint,omitempty"`
	TokenEndpoint                      string   `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint              string   `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                   string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                 string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint        string   `json:"device_authorization_endpoint,omitempty"`
	JwksURI                            string   `json:"jwks_uri,omitempty"`
	TokenEndpointAuthMethods           []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// Discover fetches OIDC configuration from the discovery endpoint
// If wellKnownURL is provided, it will be used as the discovery endpoint
// Otherwise, the standard discovery endpoint will be used
func (o *OIDCConfig) Discover(ctx context.Context, client *httpclient.Client) (*DiscoveryConfiguration, error) {
	var discoveryURL string
	if o.DiscoveryEndpoint != "" {
		discoveryURL = o.DiscoveryEndpoint
	} else {
		discoveryURL = strings.TrimRight(o.IssuerURL, "/") + DiscoveryEndpoint
	}

	discoveryConfig := &DiscoveryConfiguration{}
	resp, err := client.Get(ctx, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request failed with status %d", resp.StatusCode)
	}

	err = resp.JSON(discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse discovery response: %w", err)
	}

	// Validate issuer - only if using standard discovery endpoint
	if o.DiscoveryEndpoint == "" && discoveryConfig.Issuer != o.IssuerURL {
		return nil, httpclient.ErrIssuerInvalid
	}

	return discoveryConfig, nil
}
