package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
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

func (c *TokenExchangeFlow) executeTokenRequest(ctx context.Context, tokenRequest *httpclient.TokenRequest, headers map[string]string) (map[string]any, error) {
	resp, err := c.Config.Client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, tokenRequest, headers)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return nil, httpclient.WrapError(err, "token")
	}

	return tokenData, nil
}

func (c *TokenExchangeFlow) setupDPoPHeaders() (map[string]string, error) {
	headers := make(map[string]string)
	if c.FlowConfig.DPoP {
		dpopProof, err := crypto.NewDPoPProof(
			c.Config.DPoPPublicKey,
			c.Config.DPoPPrivateKey,
			"POST",
			c.Config.TokenEndpoint,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP proof: %w", err)
		}
		headers["DPoP"] = dpopProof.String()
	}
	return headers, nil
}

func (c *TokenExchangeFlow) Run(ctx context.Context) error {
	req := c.createTokenRequest()

	// Handle DPoP
	headers, err := c.setupDPoPHeaders()
	if err != nil {
		return err
	}

	// Call the token endpoint with the token exchange request
	tokenData, err := c.executeTokenRequest(ctx, req, headers)
	if err != nil {
		return err
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format token response: %w", err)
	}
	log.Outputf("%s\n", string(prettyJSON))
	return nil
}
