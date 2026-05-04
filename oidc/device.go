package oidc

import (
	"context"
	"encoding/json"
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

func (c *DeviceFlow) setupPKCE() (string, error) {
	if !c.FlowConfig.PKCE {
		return "", nil
	}
	if c.Config.ClientSecret == "" {
		c.Config.AuthMethod = httpclient.AuthMethodNone
	}
	codeVerifier, err := crypto.GeneratePKCECodeVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	return codeVerifier, nil
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
	codeVerifier, err := c.setupPKCE()
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
		err := httpclient.NewDefaultBrowserLauncher().OpenURL(verificationURI)
		if err != nil {
			logger.Errorf("failed to open verification uri %s in the default browser: %v\n", verificationURI, err)
		}
	} else {
		verificationURI := deviceAuthResp.VerificationURI
		logger.Printf("device verification uri: %s, verification code: %s\n", verificationURI, deviceAuthResp.UserCode)
		err := httpclient.NewDefaultBrowserLauncher().OpenURL(verificationURI)
		if err != nil {
			logger.Errorf("failed to open verification uri %s in the default browser: %v\n", verificationURI, err)
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

	// Handle DPoP
	headers, err := c.setupDPoPHeaders()
	if err != nil {
		return err
	}

	tokenResp, err := client.ExecutePollingTokenRequest(ctx, c.Config.TokenEndpoint, tokenReq, deviceAuthResp.Interval, headers)
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
	logger.Outputf("%s\n", string(prettyJSON))
	return nil
}
