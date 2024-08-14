package signing

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidAlgorithm = errors.New("invalid signing algorithm")
	ErrUnknownAlgorithm = errors.New("unknown signing algorithm")
)

func ValidateMethod(algorithm string, token *jwt.Token) error {
	switch GetFamilyFromSigningMethod(token.Method) {
	case HMAC:
		if GetFamily(algorithm) != HMAC {
			return ErrInvalidAlgorithm
		}
	case RSA:
		if GetFamily(algorithm) != RSA {
			return ErrInvalidAlgorithm
		}
	case ECDSA:
		if GetFamily(algorithm) != ECDSA {
			return ErrInvalidAlgorithm
		}
	case EdDSA:
		if GetFamily(algorithm) != EdDSA {
			return ErrInvalidAlgorithm
		}
	case RSAPSS:
		if GetFamily(algorithm) != RSAPSS {
			return ErrInvalidAlgorithm
		}
	default:
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, token.Header["alg"])
	}
	return nil
}
