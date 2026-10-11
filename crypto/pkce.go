package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GeneratePKCECodeVerifier() (string, error) {
	b := make([]byte, 96) // 96 bytes is the maximum length for a code verifier
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read from random to generate PKCE code verifier %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GeneratePKCECodeChallenge(codeVerifier string) string {
	sha := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// GenerateState returns a random OAuth2 state value: 32 bytes from a
// cryptographic source, base64url-encoded without padding (43 chars).
func GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read from random to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateNonce returns a random OpenID Connect nonce value: 32 bytes from a
// cryptographic source, base64url-encoded without padding (43 chars).
func GenerateNonce() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read from random to generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
