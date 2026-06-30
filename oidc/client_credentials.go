package oidc

import (
	"context"
	"fmt"

	"github.com/jentz/oidc-cli/httpclient"
)

type ClientCredentialsFlow struct {
	Config     *Config
	FlowConfig *ClientCredentialsFlowConfig
}

type ClientCredentialsFlowConfig struct {
	Scope string
}

func (c *ClientCredentialsFlow) Run(ctx context.Context) error {
	client := c.Config.Runtime.Client

	req := httpclient.CreateClientCredentialsRequest(
		c.Config.OIDC.ClientID,
		c.Config.OIDC.ClientSecret,
		c.Config.OIDC.AuthMethod,
		c.FlowConfig.Scope,
	)

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.OIDC.TokenEndpoint, req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	return c.Config.Runtime.Logger.OutputJSON(tokenData)
}
