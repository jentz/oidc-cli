package crypto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	oidccrypto "github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/crypto/cryptotest"
)

const (
	dpopMethod = "POST"
	dpopURL    = "https://as.example.com/token"
)

// TestNewDPoPProofRoundTrip mints a proof through the public NewDPoPProof API
// for every supported key type and verifies it by parsing, the way a resource
// server would. This pins DPoP correctness independent of builder internals.
func TestNewDPoPProofRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		genKey func(t *testing.T) (pub, priv any)
	}{
		{"ECDSA P-256", ecdsaKeyGen(elliptic.P256())},
		{"ECDSA P-384", ecdsaKeyGen(elliptic.P384())},
		{"ECDSA P-521", ecdsaKeyGen(elliptic.P521())},
		{"RSA 2048", rsaKeyGen(2048)},
		{"RSA 3072", rsaKeyGen(3072)},
		{"RSA 4096", rsaKeyGen(4096)},
		{"Ed25519", ed25519KeyGen()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pub, priv := tt.genKey(t)

			proof, err := oidccrypto.NewDPoPProof(pub, priv, dpopMethod, dpopURL)
			if err != nil {
				t.Fatalf("NewDPoPProof() error = %v", err)
			}

			cryptotest.VerifyDPoPProof(t, proof.String(), pub, dpopMethod, dpopURL)
		})
	}
}

// TestNewDPoPProofWrongKey asserts that verification fails when the proof is
// checked against a public key it is not bound to.
func TestNewDPoPProofWrongKey(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	proof, err := oidccrypto.NewDPoPProof(&priv.PublicKey, priv, dpopMethod, dpopURL)
	if err != nil {
		t.Fatalf("NewDPoPProof() error = %v", err)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	// Assert the specific key-binding failure, not merely any error, so the
	// test cannot pass for an unrelated reason if CheckDPoPProof regresses.
	if err := cryptotest.CheckDPoPProof(proof.String(), &other.PublicKey, dpopMethod, dpopURL); !errors.Is(err, cryptotest.ErrKeyMismatch) {
		t.Errorf("CheckDPoPProof() error = %v, want ErrKeyMismatch", err)
	}
}

// TestNewDPoPProofUnsupportedKey covers the signing-method guard: a key whose
// curve maps to no JWS algorithm must produce an error rather than a proof.
func TestNewDPoPProofUnsupportedKey(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	if _, err := oidccrypto.NewDPoPProof(&priv.PublicKey, priv, dpopMethod, dpopURL); err == nil {
		t.Error("NewDPoPProof() error = nil, want error for an unsupported curve")
	}
}

func ecdsaKeyGen(curve elliptic.Curve) func(t *testing.T) (pub, priv any) {
	return func(t *testing.T) (any, any) {
		t.Helper()
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		return &priv.PublicKey, priv
	}
}

func rsaKeyGen(bits int) func(t *testing.T) (pub, priv any) {
	return func(t *testing.T) (any, any) {
		t.Helper()
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		return &priv.PublicKey, priv
	}
}

func ed25519KeyGen() func(t *testing.T) (pub, priv any) {
	return func(t *testing.T) (any, any) {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		return pub, priv
	}
}
