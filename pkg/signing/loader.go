package signing

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func LoadSigningKey(algorithm, path string) (any, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch GetFamily(algorithm) {
	case HMAC:
		return keyData, nil
	case RSA:
		return jwt.ParseRSAPrivateKeyFromPEM(keyData)
	case ECDSA:
		return jwt.ParseECPrivateKeyFromPEM(keyData)
	case EdDSA:
		return jwt.ParseEdPrivateKeyFromPEM(keyData)
	case RSAPSS:
		return keyData, nil
	default:
		return nil, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}
}

func LoadVerifyKey(algorithm, path string) (any, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch GetFamily(algorithm) {
	case HMAC:
		return keyData, nil
	case RSA:
		return jwt.ParseRSAPublicKeyFromPEM(keyData)
	case ECDSA:
		return jwt.ParseECPublicKeyFromPEM(keyData)
	case EdDSA:
		return jwt.ParseEdPublicKeyFromPEM(keyData)
	case RSAPSS:
		return keyData, nil
	default:
		return nil, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}
}
