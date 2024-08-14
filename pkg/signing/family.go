package signing

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Family int

const (
	Unknown Family = iota
	HMAC
	RSA
	ECDSA
	EdDSA
	RSAPSS
)

var (
	ErrUnknownAlgorithm = errors.New("unknown signature algorithm")
)

var SupportedAlgorithms = []string{
	jwt.SigningMethodHS256.Name,
	jwt.SigningMethodRS256.Name,
	jwt.SigningMethodRS384.Name,
	jwt.SigningMethodRS512.Name,
	jwt.SigningMethodES256.Name,
	jwt.SigningMethodES384.Name,
	jwt.SigningMethodES512.Name,
	jwt.SigningMethodEdDSA.Alg(),
	jwt.SigningMethodPS256.Name,
	jwt.SigningMethodPS384.Name,
	jwt.SigningMethodPS512.Name,
}

func GetFamilyFromSigningMethod(method jwt.SigningMethod) Family {
	return GetFamily(method.Alg())
}

func GetFamily(algorithm string) Family {
	switch algorithm {
	case jwt.SigningMethodHS256.Name, jwt.SigningMethodHS512.Name:
		return HMAC
	case jwt.SigningMethodRS256.Name, jwt.SigningMethodRS384.Name, jwt.SigningMethodRS512.Name:
		return RSA
	case jwt.SigningMethodES256.Name, jwt.SigningMethodES384.Name, jwt.SigningMethodES512.Name:
		return ECDSA
	case jwt.SigningMethodEdDSA.Alg():
		return EdDSA
	case jwt.SigningMethodPS256.Name, jwt.SigningMethodPS384.Name, jwt.SigningMethodPS512.Name:
		return RSAPSS
	default:
		return Unknown
	}
}

func GetMethod(algorithm string) (method jwt.SigningMethod) {
	switch algorithm {
	case jwt.SigningMethodHS256.Name:
		method = jwt.SigningMethodHS256
	case jwt.SigningMethodHS512.Name:
		method = jwt.SigningMethodHS512
	case jwt.SigningMethodRS256.Name:
		method = jwt.SigningMethodRS256
	case jwt.SigningMethodRS384.Name:
		method = jwt.SigningMethodRS384
	case jwt.SigningMethodRS512.Name:
		method = jwt.SigningMethodRS512
	case jwt.SigningMethodES256.Name:
		method = jwt.SigningMethodES256
	case jwt.SigningMethodES384.Name:
		method = jwt.SigningMethodES384
	case jwt.SigningMethodES512.Name:
		method = jwt.SigningMethodES512
	case jwt.SigningMethodEdDSA.Alg():
		method = jwt.SigningMethodEdDSA
	case jwt.SigningMethodPS256.Name:
		method = jwt.SigningMethodPS256
	case jwt.SigningMethodPS384.Name:
		method = jwt.SigningMethodPS384
	case jwt.SigningMethodPS512.Name:
		method = jwt.SigningMethodPS512
	default:
		method = nil
	}
	return
}

func ValidateAlgorithm(algorithm string) error {
	for _, a := range SupportedAlgorithms {
		if a == algorithm {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrUnknownAlgorithm, algorithm)
}
