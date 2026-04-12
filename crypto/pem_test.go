package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParsePublicKeyPEMBlock(t *testing.T) {
	t.Parallel()
	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyRSA := &privateKeyRSA.PublicKey
	x509RSA, _ := x509.MarshalPKIXPublicKey(publicKeyRSA)

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyECDSA := &privateKeyECDSA.PublicKey
	x509ECDSA, _ := x509.MarshalPKIXPublicKey(publicKeyECDSA)

	publicKeyEd25519, _, _ := ed25519.GenerateKey(rand.Reader)
	x509Ed25519, _ := x509.MarshalPKIXPublicKey(publicKeyEd25519)

	pemBlockRSA := &pem.Block{Type: "PUBLIC KEY", Bytes: x509RSA}
	pemBlockECDSA := &pem.Block{Type: "PUBLIC KEY", Bytes: x509ECDSA}
	pemBlockEd25519 := &pem.Block{Type: "PUBLIC KEY", Bytes: x509Ed25519}
	pemBlockInvalid := &pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}
	pemBlockUnsupported := &pem.Block{Type: "UNSUPPORTED PUBLIC KEY", Bytes: []byte("unsupported")}

	tests := []struct {
		name    string
		block   *pem.Block
		wantErr bool
	}{
		{"valid rsa public key", pemBlockRSA, false},
		{"valid ecdsa public key", pemBlockECDSA, false},
		{"valid ed25519 public key", pemBlockEd25519, false},
		{"invalid public key", pemBlockInvalid, true},
		{"unsupported public key header", pemBlockUnsupported, true},
		{"empty pem block", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePublicKeyPEMBlock(tt.block)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKeyPEMBlock() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePrivateKeyPEMBlock(t *testing.T) {
	t.Parallel()
	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	x509RSAPKCS1 := x509.MarshalPKCS1PrivateKey(privateKeyRSA)
	x509RSAPKCS8, _ := x509.MarshalPKCS8PrivateKey(privateKeyRSA)

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x509ECDSAEC, _ := x509.MarshalECPrivateKey(privateKeyECDSA)
	x509ECDSAPKCS8, _ := x509.MarshalPKCS8PrivateKey(privateKeyECDSA)

	_, privateKeyEd25519, _ := ed25519.GenerateKey(rand.Reader)
	x509Ed25519, _ := x509.MarshalPKCS8PrivateKey(privateKeyEd25519)

	pemBlockRSAPKCS1 := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509RSAPKCS1}
	pemBlockRSAPKCS8 := &pem.Block{Type: "PRIVATE KEY", Bytes: x509RSAPKCS8}
	pemBlockECDSAEC := &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509ECDSAEC}
	pemBlockECDSAPKCS8 := &pem.Block{Type: "PRIVATE KEY", Bytes: x509ECDSAPKCS8}
	pemBlockEd25519 := &pem.Block{Type: "PRIVATE KEY", Bytes: x509Ed25519}
	pemBlockInvalid := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}
	pemBlockUnsupported := &pem.Block{Type: "UNSUPPORTED PRIVATE KEY", Bytes: []byte("unsupported")}

	tests := []struct {
		name    string
		block   *pem.Block
		wantErr bool
	}{
		{"valid rsa private key pkcs1", pemBlockRSAPKCS1, false},
		{"valid rsa private key pkcs8", pemBlockRSAPKCS8, false},
		{"valid ecdsa private key ec", pemBlockECDSAEC, false},
		{"valid ecdsa private key pkcs8", pemBlockECDSAPKCS8, false},
		{"valid ed25519 private key", pemBlockEd25519, false},
		{"invalid private key", pemBlockInvalid, true},
		{"unsupported private key header", pemBlockUnsupported, true},
		{"empty pem block", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePrivateKeyPEMBlock(tt.block)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeyPEMBlock() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
