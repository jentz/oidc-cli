package oidc

import (
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
)

// DPoPKeys owns the DPoP keypair: the files it loads from, the parsed keys, and
// the proof function that signs each token request with them. The zero value
// carries no keys, so its proof function errors rather than emitting an
// unsigned proof.
type DPoPKeys struct {
	PrivateKeyFile string
	PublicKeyFile  string
	Public         any
	Private        any
}

// Load parses the configured private and public key files into the keypair.
// An empty file path leaves that key unset.
func (k *DPoPKeys) Load() error {
	// Parse the private key if provided
	if k.PrivateKeyFile != "" {
		block, err := crypto.ReadPEMBlockFromFile(k.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("could not read private key file: %w", err)
		}
		k.Private, err = crypto.ParsePrivateKeyPEMBlock(block)
		if err != nil {
			return fmt.Errorf("could not parse private key: %w", err)
		}
	}

	// Parse the public key if provided
	if k.PublicKeyFile != "" {
		block, err := crypto.ReadPEMBlockFromFile(k.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}
		k.Public, err = crypto.ParsePublicKeyPEMBlock(block)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}
	return nil
}

// ProofFunc returns a function that mints a fresh DPoP proof for each token
// request, signed with the loaded keypair. It errors when a key is absent
// rather than emitting an unsigned proof.
func (k DPoPKeys) ProofFunc() httpclient.DPoPProofFunc {
	return func(method, url string) (string, error) {
		proof, err := crypto.NewDPoPProof(k.Public, k.Private, method, url)
		if err != nil {
			return "", err
		}
		return proof.String(), nil
	}
}
