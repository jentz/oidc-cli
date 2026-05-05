package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
)

type TokenRefreshFlow struct {
	Config     *Config
	FlowConfig *TokenRefreshFlowConfig
}

type TokenRefreshFlowConfig struct {
	Scopes       string
	RefreshToken string
	DPoP         bool
}

func (c *TokenRefreshFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := httpclient.CreateRefreshTokenRequest(c.Config.ClientID, c.Config.ClientSecret, c.Config.AuthMethod, c.FlowConfig.RefreshToken, c.FlowConfig.Scopes)

	// Handle DPoP
	if c.FlowConfig.DPoP {
		req.DPoP = func(method, url string) (string, error) {
			proof, err := crypto.NewDPoPProof(c.Config.DPoPPublicKey, c.Config.DPoPPrivateKey, method, url)
			if err != nil {
				return "", err
			}
			return proof.String(), nil
		}
	}

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format token response: %w", err)
	}
	c.Config.Logger.Outputf("%s\n", string(prettyJSON))
	return nil
}
