package oidc

import (
	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
)

// DPoPKeys holds the parsed DPoP keypair and vends the proof function that
// signs each token request. The zero value carries no keys, so its proof
// function errors rather than emitting an unsigned proof.
type DPoPKeys struct {
	Public  any
	Private any
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
