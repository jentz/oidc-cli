package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/httpclient"
)

type IntrospectFlow struct {
	Config     *Config
	FlowConfig *IntrospectFlowConfig
}

type IntrospectFlowConfig struct {
	BearerToken     string
	Token           string
	TokenTypeHint   string
	AcceptMediaType string
	CustomArgs      *httpclient.CustomArgs
}

func (c *IntrospectFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := &httpclient.IntrospectionRequest{
		AuthMethod:      c.Config.AuthMethod,
		ClientID:        c.Config.ClientID,
		ClientSecret:    c.Config.ClientSecret,
		BearerToken:     c.FlowConfig.BearerToken,
		Token:           c.FlowConfig.Token,
		TokenTypeHint:   c.FlowConfig.TokenTypeHint,
		AcceptMediaType: c.FlowConfig.AcceptMediaType,
		CustomArgs:      c.FlowConfig.CustomArgs,
	}

	resp, err := client.ExecuteIntrospectionRequest(ctx, c.Config.IntrospectionEndpoint, req, nil /* no custom headers */)
	if err != nil {
		return fmt.Errorf("introspection request failed: %w", err)
	}

	introspectionData, err := httpclient.ParseIntrospectionResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "introspection")
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(introspectionData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format introspection response: %w", err)
	}
	c.Config.Logger.Outputf("%s\n", string(prettyJSON))
	return nil
}
