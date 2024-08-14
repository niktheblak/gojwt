package signing

import (
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

func GetMethod(algorithm string) jwt.SigningMethod {
	switch algorithm {
	case jwt.SigningMethodHS256.Name:
		return jwt.SigningMethodHS256
	case jwt.SigningMethodHS512.Name:
		return jwt.SigningMethodHS512
	case jwt.SigningMethodRS256.Name:
		return jwt.SigningMethodRS256
	case jwt.SigningMethodRS384.Name:
		return jwt.SigningMethodRS384
	case jwt.SigningMethodRS512.Name:
		return jwt.SigningMethodRS512
	case jwt.SigningMethodES256.Name:
		return jwt.SigningMethodES256
	case jwt.SigningMethodES384.Name:
		return jwt.SigningMethodES384
	case jwt.SigningMethodES512.Name:
		return jwt.SigningMethodES512
	case jwt.SigningMethodEdDSA.Alg():
		return jwt.SigningMethodEdDSA
	case jwt.SigningMethodPS256.Name:
		return jwt.SigningMethodPS256
	case jwt.SigningMethodPS384.Name:
		return jwt.SigningMethodPS384
	case jwt.SigningMethodPS512.Name:
		return jwt.SigningMethodPS512
	default:
		return nil
	}
}
