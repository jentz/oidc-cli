package oidc

import (
	"context"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
)

type DeviceFlow struct {
	Config     *Config
	FlowConfig *DeviceFlowConfig
}

type DeviceFlowConfig struct {
	Scope string
	DPoP  bool
	PKCE  bool
}

func (c *DeviceFlow) Run(ctx context.Context) error {
	client := c.Config.Client
	codeVerifier, err := c.Config.setupPKCE(c.FlowConfig.PKCE)
	if err != nil {
		return err
	}

	req := &httpclient.DeviceAuthorizationRequest{
		ClientID: c.Config.ClientID,
		Scope:    c.FlowConfig.Scope,
	}

	if codeVerifier != "" {
		req.CodeChallengeMethod = "S256"
		req.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
	}

	resp, err := client.ExecuteDeviceAuthorizationRequest(ctx, c.Config.DeviceAuthorizationEndpoint, req)
	if err != nil {
		return fmt.Errorf("device authorization request failed: %w", err)
	}

	deviceAuthResp, err := httpclient.ParseDeviceAuthorizationResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "device authorization")
	}

	logger := c.Config.Logger
	if deviceAuthResp.VerificationURIComplete != "" {
		verificationURI := deviceAuthResp.VerificationURIComplete
		logger.Printf("device verification uri: %s\n", verificationURI)
		if err := client.OpenURL(verificationURI); err != nil {
			logger.Errorf("failed to open verification uri %s in the browser: %v\n", verificationURI, err)
		}
	} else {
		verificationURI := deviceAuthResp.VerificationURI
		logger.Printf("device verification uri: %s, verification code: %s\n", verificationURI, deviceAuthResp.UserCode)
		if err := client.OpenURL(verificationURI); err != nil {
			logger.Errorf("failed to open verification uri %s in the browser: %v\n", verificationURI, err)
		}
	}

	// Poll for token
	tokenReq := httpclient.CreateDeviceCodeTokenRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		deviceAuthResp.DeviceCode,
		codeVerifier,
	)

	if c.FlowConfig.DPoP {
		tokenReq.DPoP = c.Config.DPoPKeys.ProofFunc()
	}

	tokenResp, err := client.ExecutePollingTokenRequest(ctx, c.Config.TokenEndpoint, tokenReq, deviceAuthResp.Interval)
	if err != nil {
		return fmt.Errorf("polling token request failed: %w", err)
	}
	tokenData, err := httpclient.ParseTokenResponse(tokenResp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	return logger.OutputJSON(tokenData)
}
