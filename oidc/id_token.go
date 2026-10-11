package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// checkIDTokenNonce checks the nonce claim of the ID Token in a token
// response. It passes when no nonce was sent to check, or when the response
// has no ID Token. The payload is decoded without a signature check: OIDC Core
// 3.1.3.7 item 6 allows TLS server validation in its place for an ID Token
// received directly from the token endpoint. Only the JWT shape and the
// payload are read, so an unusual header or signature does not hide the nonce.
func checkIDTokenNonce(tokenData map[string]any, nonce string) error {
	if nonce == "" {
		return nil
	}
	raw, ok := tokenData["id_token"]
	if !ok {
		return nil
	}
	idToken, ok := raw.(string)
	if !ok {
		return errors.New("id_token is not a string")
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("id_token is not a JWT: got %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("id_token payload is not base64url: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("id_token payload is not a JSON object: %w", err)
	}
	got, ok := claims["nonce"]
	if !ok {
		return fmt.Errorf("nonce missing: expected %q in the id_token", nonce)
	}
	gotNonce, ok := got.(string)
	if !ok {
		return fmt.Errorf("nonce claim is not a string: got %v", got)
	}
	if gotNonce != nonce {
		return fmt.Errorf("nonce mismatch: expected %q but got %q", nonce, gotNonce)
	}
	return nil
}
