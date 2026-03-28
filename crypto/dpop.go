package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ecdsaJWK struct {
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
	Kty string `json:"kty"`
}

type rsaJWK struct {
	Exponent string `json:"e"`
	Modulus  string `json:"n"`
	Kty      string `json:"kty"`
}

type ed25519JWK struct {
	PublicKey string `json:"x"`
	Kty       string `json:"kty"`
}

type DPoPProof string

type DPoPProofBuilder struct {
	publicKey     any
	privateKey    any
	method        string
	url           string
	jti           string
	alg           string
	jwk           any
	token         *jwt.Token
	signingMethod jwt.SigningMethod
	signedToken   string
	errs          []error
}

func NewDPoPProof(publicKey any, privateKey any, method string, url string) (*DPoPProof, error) {
	d := NewDPoPProofBuilder().
		PublicKey(publicKey).
		PrivateKey(privateKey).
		Method(method).
		URL(url)
	return d.Build()
}

func (d *DPoPProof) String() string {
	return string(*d)
}

func NewDPoPProofBuilder() (d *DPoPProofBuilder) {
	return new(DPoPProofBuilder)
}

func (d *DPoPProofBuilder) PublicKey(k any) *DPoPProofBuilder {
	if k == nil {
		d.errs = append(d.errs, errors.New("publicKey cannot be nil"))
	}
	d.publicKey = k
	return d
}

func (d *DPoPProofBuilder) PrivateKey(k any) *DPoPProofBuilder {
	if k == nil {
		d.errs = append(d.errs, errors.New("privateKey cannot be nil"))
	}
	d.privateKey = k
	return d
}

func (d *DPoPProofBuilder) Method(s string) *DPoPProofBuilder {
	matched, err := regexp.MatchString("^[A-Z]+$", s)
	if err != nil {
		d.errs = append(d.errs, fmt.Errorf("error matching method with regex: %w", err))
	} else if !matched {
		d.errs = append(d.errs, errors.New("method must contain only uppercase letters"))
	}
	d.method = s
	return d
}

func (d *DPoPProofBuilder) URL(s string) *DPoPProofBuilder {
	_, err := url.Parse(s)
	if err != nil {
		d.errs = append(d.errs, fmt.Errorf("error parsing url: %w", err))
	}
	d.url = s
	return d
}

func (d *DPoPProofBuilder) Build() (*DPoPProof, error) {
	if len(d.errs) > 0 {
		return nil, errors.Join(d.errs...)
	}

	err := d.generateJTI()
	if err != nil {
		return nil, err
	}

	err = d.parseKeys()
	if err != nil {
		return nil, err
	}

	d.constructJWT()
	err = d.signJWT()
	if err != nil {
		return nil, err
	}

	p := DPoPProof(d.signedToken)
	return &p, nil
}

func (d *DPoPProofBuilder) parseKeys() error {
	switch k := d.publicKey.(type) {
	case *ecdsa.PublicKey:
		if _, ok := d.privateKey.(*ecdsa.PrivateKey); !ok {
			return errors.New("private key type does not match public key type")
		}
		d.jwk = ecdsaPublicKeyToJWK(d.publicKey.(*ecdsa.PublicKey))
		d.alg = ecdsaAlgorithmString(d.publicKey.(*ecdsa.PublicKey))
		d.signingMethod = jwt.SigningMethodES256

	case *rsa.PublicKey:
		if _, ok := d.privateKey.(*rsa.PrivateKey); !ok {
			return errors.New("private key type does not match public key type")
		}
		d.jwk = rsaPublicKeyToJWK(d.publicKey.(*rsa.PublicKey))
		d.alg = rsaAlgorithmString(d.publicKey.(*rsa.PublicKey))
		d.signingMethod = jwt.SigningMethodRS256

	case ed25519.PublicKey:
		if _, ok := d.privateKey.(ed25519.PrivateKey); !ok {
			return errors.New("private key type does not match public key type")
		}
		d.jwk = ed25519PublicKeyToJWK(d.publicKey.(ed25519.PublicKey))
		d.alg = ed25519AlgorithmString()
		d.signingMethod = jwt.SigningMethodEdDSA

	default:
		return fmt.Errorf("unsupported public key type: %T", k)
	}
	return nil
}

func (d *DPoPProofBuilder) constructJWT() {
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": d.alg,
		"jwk": d.jwk,
	}
	claims := jwt.MapClaims{
		"jti": d.jti,
		"htm": d.method,
		"htu": d.url,
		"iat": time.Now().Unix(),
	}
	d.token = jwt.NewWithClaims(d.signingMethod, claims)
	d.token.Header = header
}

func (d *DPoPProofBuilder) signJWT() error {
	signedToken, err := d.token.SignedString(d.privateKey)
	if err != nil {
		return fmt.Errorf("error signing DPoP JWT: %w", err)
	}
	d.signedToken = signedToken
	return nil
}

func (d *DPoPProofBuilder) generateJTI() error {
	randomBytes := make([]byte, 30)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return fmt.Errorf("error generating random bytes: %w", err)
	}
	hash := sha256.Sum256(randomBytes)
	d.jti = base64.RawURLEncoding.EncodeToString(hash[:])
	return nil
}

func ecdsaPublicKeyToJWK(k *ecdsa.PublicKey) any {
	coordSize := (k.Curve.Params().BitSize + 7) / 8
	raw, _ := k.Bytes() // uncompressed SEC 1: 0x04 || X || Y, each coord zero-padded to coordSize

	return &ecdsaJWK{
		X:   base64.RawURLEncoding.EncodeToString(raw[1 : 1+coordSize]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[1+coordSize : 1+2*coordSize]),
		Crv: k.Curve.Params().Name,
		Kty: "EC",
	}
}

func rsaPublicKeyToJWK(k *rsa.PublicKey) any {
	return &rsaJWK{
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		Modulus:  base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		Kty:      "RSA",
	}
}

func ed25519PublicKeyToJWK(k ed25519.PublicKey) any {
	return &ed25519JWK{
		PublicKey: base64.RawURLEncoding.EncodeToString(k),
		Kty:       "OKP",
	}
}

func ecdsaAlgorithmString(publicKey *ecdsa.PublicKey) string {
	switch publicKey.Params().BitSize {
	case 256:
		return "ES256"
	case 384:
		return "ES384"
	case 521:
		return "ES512"
	default:
		return ""
	}
}

func rsaAlgorithmString(publicKey *rsa.PublicKey) string {
	switch bits := publicKey.N.BitLen(); {
	case bits >= 4096:
		return "RS512"
	case bits >= 3072:
		return "RS384"
	case bits >= 2048:
		return "RS256"
	default:
		return ""
	}
}

func ed25519AlgorithmString() string {
	return "EdDSA"
}
