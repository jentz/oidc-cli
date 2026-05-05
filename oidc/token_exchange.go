package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
)

type TokenExchangeFlow struct {
	Config     *Config
	FlowConfig *TokenExchangeFlowConfig
}

type TokenExchangeFlowConfig struct {
	Resource           string
	Audience           string
	Scope              string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	DPoP               bool
}

func (c *TokenExchangeFlow) createTokenRequest() *httpclient.TokenRequest {
	input := httpclient.TokenExchangeInput{
		Resource:           c.FlowConfig.Resource,
		Audience:           c.FlowConfig.Audience,
		Scope:              c.FlowConfig.Scope,
		RequestedTokenType: c.FlowConfig.RequestedTokenType,
		SubjectToken:       c.FlowConfig.SubjectToken,
		SubjectTokenType:   c.FlowConfig.SubjectTokenType,
		ActorToken:         c.FlowConfig.ActorToken,
		ActorTokenType:     c.FlowConfig.ActorTokenType,
	}

	req := httpclient.CreateTokenExchangeRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		input)

	return req
}

func (c *TokenExchangeFlow) executeTokenRequest(ctx context.Context, tokenRequest *httpclient.TokenRequest) (map[string]any, error) {
	resp, err := c.Config.Client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, tokenRequest)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return nil, httpclient.WrapError(err, "token")
	}

	return tokenData, nil
}

func (c *TokenExchangeFlow) Run(ctx context.Context) error {
	req := c.createTokenRequest()

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

	// Call the token endpoint with the token exchange request
	tokenData, err := c.executeTokenRequest(ctx, req)
	if err != nil {
		return err
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format token response: %w", err)
	}
	c.Config.Logger.Outputf("%s\n", string(prettyJSON))
	return nil
}
