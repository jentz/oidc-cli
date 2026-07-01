// Package cryptotest provides reusable test helpers for asserting that DPoP
// proofs produced by the crypto package are correct.
//
// The helpers parse a proof the way a resource server would — reconstructing
// the public key from the embedded JWK, verifying the signature against it,
// and checking the RFC 9449 claim shape — rather than reaching into builder
// internals. They live in a standalone, importable package so the same
// assertions can be shared by the crypto tests and the oidc flow tests.
package cryptotest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// dpopAlgorithms are the JWS algorithms a DPoP proof may legitimately use.
// Restricting the parser to this set rejects "none" and any unexpected
// algorithm before signature verification.
var dpopAlgorithms = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA"}

// ErrKeyMismatch is returned by CheckDPoPProof when the proof is valid but its
// embedded JWK does not match the expected public key. It is a distinct
// sentinel so negative tests can assert that the key-binding check failed,
// rather than accepting any verification error.
var ErrKeyMismatch = errors.New("embedded jwk does not match the expected public key")

// VerifyDPoPProof asserts that proof is a well-formed RFC 9449 DPoP proof bound
// to pub, failing tb otherwise. It is the assertion-style entry point for
// happy-path tests; use CheckDPoPProof for negative cases that expect failure.
func VerifyDPoPProof(tb testing.TB, proof string, pub crypto.PublicKey, wantHTM, wantHTU string) {
	tb.Helper()
	if err := CheckDPoPProof(proof, pub, wantHTM, wantHTU); err != nil {
		tb.Fatalf("DPoP proof verification failed: %v", err)
	}
}

// CheckDPoPProof verifies proof the way a resource server would: it parses the
// JWT, reconstructs the public key from the embedded JWK to check the
// signature, confirms that key matches pub, and validates the RFC 9449 claim
// shape (the dpop+jwt header type, the htm/htu claims, a non-empty jti, and a
// recent iat). It returns a non-nil error describing the first problem found,
// so callers can assert that verification fails — for example with a
// mismatched key.
func CheckDPoPProof(proof string, pub crypto.PublicKey, wantHTM, wantHTU string) error {
	var embedded crypto.PublicKey
	token, err := jwt.Parse(proof, func(t *jwt.Token) (any, error) {
		var keyErr error
		embedded, keyErr = publicKeyFromJWK(t.Header["jwk"])
		if keyErr != nil {
			return nil, keyErr
		}
		return embedded, nil
	}, jwt.WithValidMethods(dpopAlgorithms))
	if err != nil {
		return fmt.Errorf("parsing proof: %w", err)
	}

	typ, ok := token.Header["typ"].(string)
	if !ok {
		return fmt.Errorf("header typ = %v, want a \"dpop+jwt\" string", token.Header["typ"])
	}
	if typ != "dpop+jwt" {
		return fmt.Errorf("header typ = %q, want \"dpop+jwt\"", typ)
	}

	if !publicKeysEqual(embedded, pub) {
		return ErrKeyMismatch
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("claims type = %T, want jwt.MapClaims", token.Claims)
	}
	htm, ok := claims["htm"].(string)
	if !ok {
		return fmt.Errorf("htm claim = %v, want a %q string", claims["htm"], wantHTM)
	}
	if htm != wantHTM {
		return fmt.Errorf("htm claim = %q, want %q", htm, wantHTM)
	}
	htu, ok := claims["htu"].(string)
	if !ok {
		return fmt.Errorf("htu claim = %v, want a %q string", claims["htu"], wantHTU)
	}
	if htu != wantHTU {
		return fmt.Errorf("htu claim = %q, want %q", htu, wantHTU)
	}
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		return errors.New("jti claim is missing or empty")
	}
	return checkRecentIAT(claims)
}

// publicKey is the Equal method common to the crypto/ecdsa, crypto/rsa, and
// crypto/ed25519 public key types, used to compare an embedded key against the
// expected one.
type publicKey interface {
	Equal(x crypto.PublicKey) bool
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	key, ok := a.(publicKey)
	if !ok {
		return false
	}
	return key.Equal(b)
}

// publicKeyFromJWK reconstructs a public key from a parsed JWK header value.
func publicKeyFromJWK(raw any) (crypto.PublicKey, error) {
	jwk, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jwk header is missing or not an object (got %T)", raw)
	}
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("jwk kty is missing or not a string (got %T)", jwk["kty"])
	}
	switch kty {
	case "EC":
		return ecdsaKeyFromJWK(jwk)
	case "RSA":
		return rsaKeyFromJWK(jwk)
	case "OKP":
		return ed25519KeyFromJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", kty)
	}
}

func ecdsaKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("jwk crv is missing or not a string (got %T)", jwk["crv"])
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ec curve %q", crv)
	}
	x, err := decodeBigInt(jwk, "x")
	if err != nil {
		return nil, err
	}
	y, err := decodeBigInt(jwk, "y")
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func rsaKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	n, err := decodeBigInt(jwk, "n")
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeField(jwk, "e")
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("rsa exponent is out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func ed25519KeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	b, err := decodeField(jwk, "x")
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key length = %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func decodeBigInt(jwk map[string]any, field string) (*big.Int, error) {
	b, err := decodeField(jwk, field)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeField(jwk map[string]any, field string) ([]byte, error) {
	s, ok := jwk[field].(string)
	if !ok {
		return nil, fmt.Errorf("jwk field %q is missing or not a string", field)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding jwk field %q: %w", field, err)
	}
	return b, nil
}

func checkRecentIAT(claims jwt.MapClaims) error {
	raw, ok := claims["iat"]
	if !ok {
		return errors.New("iat claim is missing")
	}
	secs, ok := raw.(float64)
	if !ok {
		return fmt.Errorf("iat claim type = %T, want a number", raw)
	}
	iat := time.Unix(int64(secs), 0)
	now := time.Now()
	if iat.After(now.Add(5 * time.Second)) {
		return fmt.Errorf("iat %s is in the future (now %s)", iat, now)
	}
	if now.Sub(iat) > time.Minute {
		return fmt.Errorf("iat %s is more than a minute in the past (now %s)", iat, now)
	}
	return nil
}
