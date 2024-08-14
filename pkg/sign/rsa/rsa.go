package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/niktheblak/gojwt/pkg/sign"
)

type rsaSigner struct {
	hash       crypto.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func RS256(privateKey *rsa.PrivateKey) sign.Signer {
	return &rsaSigner{
		hash:       crypto.SHA256,
		publicKey:  &privateKey.PublicKey,
		privateKey: privateKey,
	}
}

func RS256Verifier(publicKey *rsa.PublicKey) sign.Signer {
	return &rsaSigner{
		publicKey: publicKey,
	}
}

func (s *rsaSigner) Algorithm() sign.Algorithm {
	return sign.RS256
}

func (s *rsaSigner) Sign(data string) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key is not set")
	}
	h := s.hash.New()
	hashed := h.Sum([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hash, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (s *rsaSigner) Verify(data string, signature []byte) error {
	if s.publicKey == nil {
		return fmt.Errorf("public key is not set")
	}
	if err := rsa.VerifyPKCS1v15(s.publicKey, s.hash, []byte(data), signature); err != nil {
		return fmt.Errorf("%w: %w", sign.ErrInvalidSignature, err)
	}
	return nil
}

func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("unsupported key type %T", key)
	default:
		return nil, fmt.Errorf("unsupported block type %q", block.Type)
	}
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported key type %T", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported block type %q", block.Type)
	}
}
