package oidc

import (
	"context"
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
	client := c.Config.Runtime.Client

	req := &httpclient.IntrospectionRequest{
		AuthMethod:      c.Config.OIDC.AuthMethod,
		ClientID:        c.Config.OIDC.ClientID,
		ClientSecret:    c.Config.OIDC.ClientSecret,
		BearerToken:     c.FlowConfig.BearerToken,
		Token:           c.FlowConfig.Token,
		TokenTypeHint:   c.FlowConfig.TokenTypeHint,
		AcceptMediaType: c.FlowConfig.AcceptMediaType,
		CustomArgs:      c.FlowConfig.CustomArgs,
	}

	resp, err := client.ExecuteIntrospectionRequest(ctx, c.Config.OIDC.IntrospectionEndpoint, req, nil /* no custom headers */)
	if err != nil {
		return fmt.Errorf("introspection request failed: %w", err)
	}

	introspectionData, err := httpclient.ParseIntrospectionResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "introspection")
	}

	return c.Config.Runtime.Logger.OutputJSON(introspectionData)
}
