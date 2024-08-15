package signing

import (
	"errors"
	"fmt"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type Family int

const (
	HMAC Family = iota
	RSA
	ECDSA
	EdDSA
	RSAPSS
)

var (
	ErrUnknownFamily    = errors.New("unknown family")
	ErrUnknownAlgorithm = errors.New("unknown signing algorithm")
)

var Methods = map[string]jwt.SigningMethod{
	jwt.SigningMethodHS256.Name:  jwt.SigningMethodHS256,
	jwt.SigningMethodRS256.Name:  jwt.SigningMethodRS256,
	jwt.SigningMethodRS384.Name:  jwt.SigningMethodRS384,
	jwt.SigningMethodRS512.Name:  jwt.SigningMethodRS512,
	jwt.SigningMethodES256.Name:  jwt.SigningMethodES256,
	jwt.SigningMethodES384.Name:  jwt.SigningMethodES384,
	jwt.SigningMethodES512.Name:  jwt.SigningMethodES512,
	jwt.SigningMethodEdDSA.Alg(): jwt.SigningMethodEdDSA,
	jwt.SigningMethodPS256.Name:  jwt.SigningMethodPS256,
	jwt.SigningMethodPS384.Name:  jwt.SigningMethodPS384,
	jwt.SigningMethodPS512.Name:  jwt.SigningMethodPS512,
}

var Families = map[Family][]string{
	HMAC:   {jwt.SigningMethodHS256.Name, jwt.SigningMethodHS512.Name},
	RSA:    {jwt.SigningMethodRS256.Name, jwt.SigningMethodRS384.Name, jwt.SigningMethodRS512.Name},
	ECDSA:  {jwt.SigningMethodES256.Name, jwt.SigningMethodES384.Name, jwt.SigningMethodES512.Name},
	EdDSA:  {jwt.SigningMethodEdDSA.Alg()},
	RSAPSS: {jwt.SigningMethodPS256.Name, jwt.SigningMethodPS384.Name, jwt.SigningMethodPS512.Name},
}

func GetFamily(algorithm string) (Family, error) {
	for family, algorithms := range Families {
		if slices.Contains(algorithms, algorithm) {
			return family, nil
		}
	}
	return 0, ErrUnknownFamily
}

func GetFamilyFromSigningMethod(method jwt.SigningMethod) (Family, error) {
	return GetFamily(method.Alg())
}

func ValidateAlgorithm(algorithm string) error {
	_, ok := Methods[algorithm]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAlgorithm, algorithm)
	}
	return nil
}
