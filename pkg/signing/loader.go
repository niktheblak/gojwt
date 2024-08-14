package signing

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadSigningKey(algorithm, path string) (any, error) {
	switch GetFamily(algorithm) {
	case HMAC:
		return os.ReadFile(path)
	case RSA:
		return LoadRSAPrivateKey(path)
	case ECDSA:
		return nil, fmt.Errorf("not implemented")
	case EdDSA:
		return nil, fmt.Errorf("not implemented")
	case RSAPSS:
		return nil, fmt.Errorf("not implemented")
	default:
		return nil, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}
}

func LoadVerifyKey(algorithm, path string) (any, error) {
	switch GetFamily(algorithm) {
	case HMAC:
		return os.ReadFile(path)
	case RSA:
		return LoadRSAPublicKey(path)
	case ECDSA:
		return nil, fmt.Errorf("not implemented")
	case EdDSA:
		return nil, fmt.Errorf("not implemented")
	case RSAPSS:
		return nil, fmt.Errorf("not implemented")
	default:
		return nil, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}
}

func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKey(data)
}

func ParseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
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

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKey(data)
}

func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found")
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
