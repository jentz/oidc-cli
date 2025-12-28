package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

type DeviceFlow struct {
	Config     *Config
	FlowConfig *DeviceFlowConfig
}

type DeviceFlowConfig struct {
	Scope string
	DPoP  bool
}

func (c *DeviceFlow) setupDPoPHeaders() (map[string]string, error) {
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

func (c *DeviceFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := &httpclient.DeviceAuthorizationRequest{
		ClientID: c.Config.ClientID,
		Scope:    c.FlowConfig.Scope,
	}

	// Handle DPoP
	headers, err := c.setupDPoPHeaders()
	if err != nil {
		return err
	}

	resp, err := client.ExecuteDeviceAuthorizationRequest(ctx, c.Config.DeviceAuthorizationEndpoint, req, headers)
	if err != nil {
		return fmt.Errorf("device authorization request failed: %w", err)
	}

	deviceAuthResp, err := httpclient.ParseDeviceAuthorizationResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "device authorization")
	}

	// Print link to verification URI
	if deviceAuthResp.VerificationURIComplete != "" {
		log.Printf("device verification uri: %s\n", deviceAuthResp.VerificationURIComplete)
		httpclient.NewDefaultBrowserLauncher().OpenURL(deviceAuthResp.VerificationURIComplete)
	} else {
		log.Printf("device verification uri: %s, verification code: %s\n", deviceAuthResp.VerificationURI, deviceAuthResp.UserCode)
		httpclient.NewDefaultBrowserLauncher().OpenURL(deviceAuthResp.VerificationURI)
	}

	// Poll for token
	tokenReq := httpclient.CreateDeviceCodeTokenRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		deviceAuthResp.DeviceCode,
	)
	tokenResp, err := client.ExecutePollingTokenRequest(ctx, c.Config.TokenEndpoint, tokenReq, deviceAuthResp.Interval)
	if err != nil {
		return fmt.Errorf("polling token request failed: %w", err)
	}
	tokenData, err := httpclient.ParseTokenResponse(tokenResp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format token response: %w", err)
	}
	log.Outputf("%s\n", string(prettyJSON))
	return nil
}
