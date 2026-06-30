package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

// writeKeyPEM marshals der into a PEM block of the given type and writes it to a
// file under dir, returning the path.
func writeKeyPEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// TestDPoPKeysLoadParsesUsableKeypair checks that Load reads the configured key
// files into a keypair that actually works: the proof function it then vends
// produces a proof a resource server accepts, bound to the public key on disk
// and signed by the private key on disk.
func TestDPoPKeysLoadParsesUsableKeypair(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	dir := t.TempDir()
	keys := DPoPKeys{
		PrivateKeyFile: writeKeyPEM(t, dir, "priv.pem", "PRIVATE KEY", privDER),
		PublicKeyFile:  writeKeyPEM(t, dir, "pub.pem", "PUBLIC KEY", pubDER),
	}

	if err := keys.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

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

// TestDPoPKeysLoadMissingFile pins that Load surfaces a read failure naming the
// key it could not load, rather than silently leaving the keypair unset.
func TestDPoPKeysLoadMissingFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		private     bool
		wantContain string
	}{
		{
			name:        "private key file missing",
			private:     true,
			wantContain: "could not read private key file",
		},
		{
			name:        "public key file missing",
			private:     false,
			wantContain: "failed to read public key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			missing := filepath.Join(t.TempDir(), "missing.pem")
			var keys DPoPKeys
			if tt.private {
				keys.PrivateKeyFile = missing
			} else {
				keys.PublicKeyFile = missing
			}

			err := keys.Load()
			if err == nil {
				t.Fatal("Load error = nil, want error for missing file")
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantContain)
			}
		})
	}
}

// TestDPoPKeysLoadNoFiles pins that Load with no configured files leaves both
// keys unset rather than erroring.
func TestDPoPKeysLoadNoFiles(t *testing.T) {
	t.Parallel()

	keys := DPoPKeys{}
	if err := keys.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if keys.Private != nil || keys.Public != nil {
		t.Errorf("keys = %+v, want both Private and Public nil", keys)
	}
}
