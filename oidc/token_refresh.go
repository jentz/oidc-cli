package oidc

import (
	"context"
	"fmt"

	"github.com/jentz/oidc-cli/httpclient"
)

type TokenRefreshFlow struct {
	Config     *Config
	FlowConfig *TokenRefreshFlowConfig
}

type TokenRefreshFlowConfig struct {
	Scope        string
	RefreshToken string
	DPoP         bool
}

func (c *TokenRefreshFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := httpclient.CreateRefreshTokenRequest(c.Config.ClientID, c.Config.ClientSecret, c.Config.AuthMethod, c.FlowConfig.RefreshToken, c.FlowConfig.Scope)

	// Handle DPoP
	if c.FlowConfig.DPoP {
		req.DPoP = c.Config.DPoPKeys.ProofFunc()
	}

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	return c.Config.Logger.OutputJSON(tokenData)
}
