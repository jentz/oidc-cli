package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jentz/oidc-cli/crypto/cryptotest"
)

// TestDPoPKeysProofFuncSignsWithLoadedKeys checks that the proof function the
// owner vends produces a proof a resource server accepts: bound to the loaded
// public key, with the method and endpoint it was asked to sign.
func TestDPoPKeysProofFuncSignsWithLoadedKeys(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keys := DPoPKeys{Public: &priv.PublicKey, Private: priv}

	const (
		method = "POST"
		url    = "https://op.example.com/token"
	)

	proof, err := keys.ProofFunc()(method, url)
	if err != nil {
		t.Fatalf("ProofFunc returned error: %v", err)
	}
	cryptotest.VerifyDPoPProof(t, proof, &priv.PublicKey, method, url)
}

// TestDPoPKeysProofFuncWithoutKeys pins that a proof function vended without a
// loaded keypair fails loudly instead of emitting an unsigned or empty proof.
func TestDPoPKeysProofFuncWithoutKeys(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tests := []struct {
		name string
		keys DPoPKeys
		// wantContain are substrings the error must name; wantAbsent are the
		// substrings it must not, so a one-key case cannot pass on the other
		// key's message if the two were ever swapped.
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "both keys absent",
			keys:        DPoPKeys{},
			wantContain: []string{"publicKey cannot be nil", "privateKey cannot be nil"},
		},
		{
			name:        "private key absent",
			keys:        DPoPKeys{Public: &priv.PublicKey},
			wantContain: []string{"privateKey cannot be nil"},
			wantAbsent:  []string{"publicKey cannot be nil"},
		},
		{
			name:        "public key absent",
			keys:        DPoPKeys{Private: priv},
			wantContain: []string{"publicKey cannot be nil"},
			wantAbsent:  []string{"privateKey cannot be nil"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			proof, err := tt.keys.ProofFunc()("POST", "https://op.example.com/token")
			if err == nil {
				t.Fatal("ProofFunc error = nil, want error for absent key")
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("error = %q, want it to omit %q", err, absent)
				}
			}
			if proof != "" {
				t.Errorf("proof = %q, want empty on error", proof)
			}
		})
	}
}
