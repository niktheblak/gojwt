package signing

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidAlgorithm = errors.New("invalid signing algorithm")
)

func ValidateMethod(algorithm string, token *jwt.Token) error {
	family, err := GetFamilyFromSigningMethod(token.Method)
	if err != nil {
		return err
	}
	tokenFamily, err := GetFamily(algorithm)
	if err != nil {
		return err
	}
	switch family {
	case HMAC:
		if tokenFamily != HMAC {
			return ErrInvalidAlgorithm
		}
	case RSA:
		if tokenFamily != RSA {
			return ErrInvalidAlgorithm
		}
	case ECDSA:
		if tokenFamily != ECDSA {
			return ErrInvalidAlgorithm
		}
	case EdDSA:
		if tokenFamily != EdDSA {
			return ErrInvalidAlgorithm
		}
	case RSAPSS:
		if tokenFamily != RSAPSS {
			return ErrInvalidAlgorithm
		}
	default:
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, token.Header["alg"])
	}
	return nil
}
