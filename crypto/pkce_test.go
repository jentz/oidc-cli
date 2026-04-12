package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePKCECodeVerifier(t *testing.T) {
	t.Parallel()
	verifier, err := GeneratePKCECodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Check length: 96 bytes base64-encoded should be 128 chars (without padding)
	if len(verifier) != 128 {
		t.Errorf("expected verifier length 128, got %d", len(verifier))
	}
	// Check valid base64url
	_, err = base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		t.Errorf("verifier is not valid base64url: %v", err)
	}
}

func TestGeneratePKCECodeChallenge(t *testing.T) {
	t.Parallel()
	verifier := "testverifier"
	challenge := GeneratePKCECodeChallenge(verifier)
	// SHA256 output is 32 bytes, base64url-encoded is 43 chars (no padding)
	if len(challenge) != 43 {
		t.Errorf("expected challenge length 43, got %d", len(challenge))
	}
	_, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		t.Errorf("challenge is not valid base64url: %v", err)
	}
}
