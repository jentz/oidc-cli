package crypto

//nolint:staticcheck // SA1019: crypto/dsa is used for test coverage of legacy/unsupported key types
import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewDPoPProofBuilder(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name       string
		privateKey any
		publicKey  any
		method     string
		url        string
	}{
		{
			name:       "create dpop proof builder",
			privateKey: privateKey,
			publicKey:  publicKey,
			method:     "POST",
			url:        "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dpopProofBuilder := NewDPoPProofBuilder().PrivateKey(tt.privateKey).PublicKey(tt.publicKey).Method(tt.method).URL(tt.url)
			if dpopProofBuilder == nil {
				t.Errorf("NewDPoPProofBuilder() = %v, want %v", dpopProofBuilder, "not nil")
			}
			if dpopProofBuilder.privateKey != tt.privateKey {
				t.Errorf("NewDPoPProofBuilder().PrivateKey() = %v, want %v", dpopProofBuilder.privateKey, tt.privateKey)
			}
			if dpopProofBuilder.publicKey != tt.publicKey {
				t.Errorf("NewDPoPProofBuilder().PublicKey() = %v, want %v", dpopProofBuilder.publicKey, tt.publicKey)
			}
			if dpopProofBuilder.method != tt.method {
				t.Errorf("NewDPoPProofBuilder().Method() = %v, want %v", dpopProofBuilder.method, tt.method)
			}
			if dpopProofBuilder.url != tt.url {
				t.Errorf("NewDPoPProofBuilder().URL() = %v, want %v", dpopProofBuilder.url, tt.url)
			}
		})
	}
}

func TestNewDPoPProofBuilderError(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name       string
		privateKey any
		publicKey  any
		method     string
		url        string
	}{
		{
			name:       "create dpop proof builder with nil for private key",
			privateKey: nil,
			publicKey:  publicKey,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop proof builder with nil for public key",
			privateKey: privateKey,
			publicKey:  nil,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop proof builder with invalid method",
			privateKey: privateKey,
			publicKey:  publicKey,
			method:     "POSTasd",
			url:        "https://example.com",
		},
		{
			name:       "create dpop proof builder with invalid url",
			privateKey: privateKey,
			publicKey:  publicKey,
			method:     "POST",
			url:        "http://example.com:example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dpopProofBuilder := NewDPoPProofBuilder().PrivateKey(tt.privateKey).PublicKey(tt.publicKey).Method(tt.method).URL(tt.url)
			if len(dpopProofBuilder.errs) < 1 {
				t.Errorf("NewDPoPProofBuilder() = %v, want %v", dpopProofBuilder.errs, "not empty")
			}
		})
	}
}

func TestParseKeys(t *testing.T) {
	t.Parallel()
	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyRSA := &privateKeyRSA.PublicKey

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyECDSA := &privateKeyECDSA.PublicKey

	publicKeyEd25519, privateKeyEd25519, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name                  string
		privateKey            any
		publicKey             any
		expectedSigningMethod jwt.SigningMethod
	}{
		{
			name:                  "parse rsa keys",
			privateKey:            privateKeyRSA,
			publicKey:             publicKeyRSA,
			expectedSigningMethod: jwt.SigningMethodRS256,
		},
		{
			name:                  "parse ecdsa keys",
			privateKey:            privateKeyECDSA,
			publicKey:             publicKeyECDSA,
			expectedSigningMethod: jwt.SigningMethodES256,
		},
		{
			name:                  "parse ed25519 keys",
			privateKey:            privateKeyEd25519,
			publicKey:             publicKeyEd25519,
			expectedSigningMethod: jwt.SigningMethodEdDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builder := &DPoPProofBuilder{
				privateKey: tt.privateKey,
				publicKey:  tt.publicKey,
			}
			err := builder.parseKeys()
			if err != nil {
				t.Errorf("parseKeys() error = %v, wantErr %v", err, nil)
			}
			if builder.signingMethod != tt.expectedSigningMethod {
				t.Errorf("parseKeys() signingMethod = %v, want %v", builder.signingMethod, tt.expectedSigningMethod)
			}
		})
	}
}

func TestParseKeysError(t *testing.T) {
	t.Parallel()
	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyRSA := &privateKeyRSA.PublicKey

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyECDSA := &privateKeyECDSA.PublicKey

	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	if err != nil {
		panic(err)
	}

	var privateKeyDSA dsa.PrivateKey
	privateKeyDSA.Parameters = params
	err = dsa.GenerateKey(&privateKeyDSA, rand.Reader)
	if err != nil {
		panic(err)
	}

	publicKeyDSA := privateKeyDSA.PublicKey

	tests := []struct {
		name       string
		privateKey any
		publicKey  any
	}{
		{
			name:       "parse nil keys",
			privateKey: nil,
			publicKey:  nil,
		},
		{
			name:       "parse invalid keys",
			privateKey: "1234",
			publicKey:  "1234",
		},
		{
			name:       "parse with public key as private key",
			privateKey: publicKeyRSA,
			publicKey:  publicKeyRSA,
		},
		{
			name:       "parse with private key as public key",
			privateKey: privateKeyRSA,
			publicKey:  privateKeyRSA,
		},
		{
			name:       "parse with non-matching key types",
			privateKey: privateKeyRSA,
			publicKey:  publicKeyECDSA,
		},
		{
			name:       "parse unsupported key type",
			privateKey: privateKeyDSA,
			publicKey:  publicKeyDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builder := &DPoPProofBuilder{
				privateKey: tt.privateKey,
				publicKey:  tt.publicKey,
			}
			err := builder.parseKeys()
			if err == nil {
				t.Errorf("parseKeys() error = %v, wantErr %v", err, "not nil")
			}
		})
	}
}

func TestConstructJWT(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name             string
		dpopProofBuilder *DPoPProofBuilder
	}{
		{
			name: "construct valid jwt",
			dpopProofBuilder: &DPoPProofBuilder{
				jwk:           rsaPublicKeyToJWK(publicKey),
				alg:           rsaAlgorithmString(publicKey),
				method:        "POST",
				url:           "https://example.com",
				signingMethod: jwt.SigningMethodRS256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.dpopProofBuilder.generateJTI()
			if err != nil {
				t.Errorf("generateJTI() error = %v, wantErr %v", err, nil)
			}
			tt.dpopProofBuilder.constructJWT()
			got := tt.dpopProofBuilder.token
			if got == nil {
				t.Errorf("token got = %v, want %v", got, "not nil")
			}
			if reflect.TypeOf(got) != reflect.TypeFor[*jwt.Token]() {
				t.Errorf("token type = %v, want %v", reflect.TypeOf(got), reflect.TypeFor[*jwt.Token]())
			}
			if got.Header == nil {
				t.Errorf("token.Header = %v, want %v", got.Header, "not nil")
			}
			header := got.Header
			if header["typ"] != "dpop+jwt" {
				t.Errorf("header[\"typ\"] = %v, want %v", header["typ"], "dpop+jwt")
			}
			if got.Claims == nil {
				t.Errorf("token.Claims = %v, want %v", got.Claims, "not nil")
			}
			claims := got.Claims.(jwt.MapClaims)
			if claims["jti"] != tt.dpopProofBuilder.jti {
				t.Errorf("claims[\"jti\"] = %v, want %v", claims["jti"], tt.dpopProofBuilder.jti)
			}
			if claims["htm"] != tt.dpopProofBuilder.method {
				t.Errorf("claims[\"htm\"] = %v, want %v", claims["htm"], tt.dpopProofBuilder.method)
			}
			if claims["htu"] != tt.dpopProofBuilder.url {
				t.Errorf("claims[\"htu\"] = %v, want %v", claims["htu"], tt.dpopProofBuilder.url)
			}
			if claims["iat"] == nil {
				t.Errorf("claims[\"iat\"] = %v, want %v", claims["iat"], "not nil")
			}
		})
	}
}

func TestSignJWT(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name             string
		dpopProofBuilder *DPoPProofBuilder
	}{
		{
			name: "sign valid jwt",
			dpopProofBuilder: &DPoPProofBuilder{
				privateKey:    privateKey,
				publicKey:     publicKey,
				jwk:           rsaPublicKeyToJWK(publicKey),
				alg:           rsaAlgorithmString(publicKey),
				method:        "POST",
				url:           "https://example.com",
				signingMethod: jwt.SigningMethodRS256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.dpopProofBuilder.generateJTI()
			if err != nil {
				t.Errorf("generateJTI() error = %v, wantErr %v", err, nil)
			}
			tt.dpopProofBuilder.constructJWT()
			err = tt.dpopProofBuilder.signJWT()
			if err != nil {
				t.Errorf("signJWT() error = %v, wantErr %v", err, nil)
			}
			if tt.dpopProofBuilder.signedToken == "" {
				t.Errorf("dpopProofBuilder.signedToken = %v, want %v", tt.dpopProofBuilder.signedToken, "not empty")
			}
		})
	}
}

func TestEcdsaPublicKeyToJWK(t *testing.T) {
	t.Parallel()
	curves := []struct {
		name      string
		curve     elliptic.Curve
		crv       string
		coordSize int
	}{
		{"P-256", elliptic.P256(), "P-256", 32},
		{"P-384", elliptic.P384(), "P-384", 48},
		{"P-521", elliptic.P521(), "P-521", 66},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			privateKey, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey(%s) error: %v", c.name, err)
			}
			pubKey := &privateKey.PublicKey

			result := ecdsaPublicKeyToJWK(pubKey)
			jwk, ok := result.(*ecdsaJWK)
			if !ok {
				t.Fatalf("expected *ecdsaJWK, got %T", result)
			}

			if jwk.Kty != "EC" {
				t.Errorf("Kty = %q, want %q", jwk.Kty, "EC")
			}
			if jwk.Crv != c.crv {
				t.Errorf("Crv = %q, want %q", jwk.Crv, c.crv)
			}

			// Decode X and Y and verify they match the key's actual coordinates
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				t.Fatalf("decoding X: %v", err)
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err != nil {
				t.Fatalf("decoding Y: %v", err)
			}

			// RFC 7518: coordinates MUST be the full curve byte size (zero-padded)
			if len(xBytes) != c.coordSize {
				t.Errorf("X byte length = %d, want %d", len(xBytes), c.coordSize)
			}
			if len(yBytes) != c.coordSize {
				t.Errorf("Y byte length = %d, want %d", len(yBytes), c.coordSize)
			}

			// Verify the decoded coordinates match the original key
			//nolint:staticcheck // SA1019: using deprecated X/Y fields intentionally to verify correctness
			expectedX := pubKey.X.FillBytes(make([]byte, c.coordSize))
			//nolint:staticcheck // SA1019: using deprecated X/Y fields intentionally to verify correctness
			expectedY := pubKey.Y.FillBytes(make([]byte, c.coordSize))

			gotX := new(big.Int).SetBytes(xBytes)
			gotY := new(big.Int).SetBytes(yBytes)
			wantX := new(big.Int).SetBytes(expectedX)
			wantY := new(big.Int).SetBytes(expectedY)

			if gotX.Cmp(wantX) != 0 {
				t.Errorf("X coordinate mismatch")
			}
			if gotY.Cmp(wantY) != 0 {
				t.Errorf("Y coordinate mismatch")
			}
		})
	}
}

func TestEcdsaAlgorithmString(t *testing.T) {
	t.Parallel()
	privateKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey256 := &privateKey256.PublicKey

	privateKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	publicKey384 := &privateKey384.PublicKey

	privateKey512, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	publicKey512 := &privateKey512.PublicKey

	tests := []struct {
		name     string
		key      *ecdsa.PublicKey
		expected string
	}{
		{
			name:     "valid 256-bit ecdsa key",
			key:      publicKey256,
			expected: "ES256",
		},
		{
			name:     "valid 384-bit ecdsa key",
			key:      publicKey384,
			expected: "ES384",
		},
		{
			name:     "valid 521-bit ecdsa key",
			key:      publicKey512,
			expected: "ES512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ecdsaAlgorithmString(tt.key)
			if got != tt.expected {
				t.Errorf("ecdsaAlgorithmString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRsaAlgorithmString(t *testing.T) {
	t.Parallel()
	privateKey256, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey256 := &privateKey256.PublicKey

	privateKey384, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey384 := &privateKey384.PublicKey

	privateKey512, _ := rsa.GenerateKey(rand.Reader, 4096)
	publicKey512 := &privateKey512.PublicKey

	tests := []struct {
		name     string
		key      *rsa.PublicKey
		expected string
	}{
		{
			name:     "valid 2048-bit rsa key",
			key:      publicKey256,
			expected: "RS256",
		},
		{
			name:     "valid 3072-bit rsa key",
			key:      publicKey384,
			expected: "RS384",
		},
		{
			name:     "valid 4096-bit rsa key",
			key:      publicKey512,
			expected: "RS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rsaAlgorithmString(tt.key)
			if got != tt.expected {
				t.Errorf("rsaAlgorithmString() = %v, want %v", got, tt.expected)
			}
		})
	}
}
