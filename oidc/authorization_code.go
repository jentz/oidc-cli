package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

type AuthorizationCodeFlow struct {
	Config     *Config
	FlowConfig *AuthorizationCodeFlowConfig
}

type AuthorizationCodeFlowConfig struct {
	Scopes      string
	CallbackURI string
	RedirectURI string
	Prompt      string
	AcrValues   string
	LoginHint   string
	MaxAge      string
	UILocales   string
	State       string
	CustomArgs  *httpclient.CustomArgs
	PKCE        bool
	PAR         bool
	DPoP        bool
}

func (c *AuthorizationCodeFlow) setupPKCE() (string, error) {
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

func (c *AuthorizationCodeFlow) createAuthCodeRequest(ctx context.Context, codeVerifier string) (*httpclient.AuthorizationCodeRequest, error) {
	req := &httpclient.AuthorizationCodeRequest{
		ClientID:    c.Config.ClientID,
		Scope:       c.FlowConfig.Scopes,
		RedirectURI: c.FlowConfig.RedirectURI,
		Prompt:      c.FlowConfig.Prompt,
		AcrValues:   c.FlowConfig.AcrValues,
		LoginHint:   c.FlowConfig.LoginHint,
		MaxAge:      c.FlowConfig.MaxAge,
		UILocales:   c.FlowConfig.UILocales,
		State:       c.FlowConfig.State,
		CustomArgs:  c.FlowConfig.CustomArgs,
	}
	// If the user has not explicitly set a redirect URI, use the callback URI
	if c.FlowConfig.RedirectURI == "" {
		req.RedirectURI = c.FlowConfig.CallbackURI
	}
	if codeVerifier != "" {
		req.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
		req.CodeChallengeMethod = "S256"
	}
	if c.FlowConfig.PAR {
		parParams, err := httpclient.CreateAuthorizationCodeRequestValues(req)
		if err != nil {
			return nil, fmt.Errorf("failed to create authorization code request values: %w", err)
		}
		parReq := &httpclient.PushedAuthorizationRequest{
			ClientID:     c.Config.ClientID,
			ClientSecret: c.Config.ClientSecret,
			AuthMethod:   c.Config.AuthMethod,
			Params:       parParams,
		}
		resp, err := c.Config.Client.ExecutePushedAuthorizationRequest(ctx, c.Config.PushedAuthorizationRequestEndpoint, parReq)
		if err != nil {
			return nil, fmt.Errorf("pushed authorization request failed: %w", err)
		}
		parResp, err := httpclient.ParsePushedAuthorizationResponse(resp)
		if err != nil {
			return nil, httpclient.WrapError(err, "pushed authorization")
		}
		req.RequestURI = parResp.RequestURI
	}
	return req, nil
}

func (c *AuthorizationCodeFlow) executeAuthCodeRequest(ctx context.Context, req *httpclient.AuthorizationCodeRequest) (*httpclient.AuthorizationCodeResponse, error) {
	resp, err := c.Config.Client.ExecuteAuthorizationCodeRequest(ctx, c.Config.AuthorizationEndpoint, c.FlowConfig.CallbackURI, req)
	if err != nil {
		return nil, fmt.Errorf("authorization request failed: %w", err)
	}
	return resp, nil
}

func (c *AuthorizationCodeFlow) setupDPoPHeaders() (map[string]string, error) {
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

func (c *AuthorizationCodeFlow) executeTokenRequest(ctx context.Context, code, codeVerifier string, headers map[string]string) (map[string]interface{}, error) {
	tokenRequest := httpclient.CreateAuthCodeTokenRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		code,
		c.FlowConfig.CallbackURI,
		codeVerifier,
	)
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

func (c *AuthorizationCodeFlow) Run(ctx context.Context) error {
	// Handle PKCE
	codeVerifier, err := c.setupPKCE()
	if err != nil {
		return err
	}
	// Create authorization code request (handling PAR if enabled)
	authCodeReq, err := c.createAuthCodeRequest(ctx, codeVerifier)
	if err != nil {
		return err
	}
	// Execute authorization code request
	authResp, err := c.executeAuthCodeRequest(ctx, authCodeReq)
	if err != nil {
		return err
	}
	// Handle DPoP
	headers, err := c.setupDPoPHeaders()
	if err != nil {
		return err
	}
	// Exchange authorization code for access token
	tokenData, err := c.executeTokenRequest(ctx, authResp.Code, codeVerifier, headers)
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
