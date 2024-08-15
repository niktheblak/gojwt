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

var Methods map[string]jwt.SigningMethod

func init() {
	// go-jwt doesn't make the algorithm-signing method map public so reconstruct it here
	Methods = make(map[string]jwt.SigningMethod)
	for _, algorithm := range jwt.GetAlgorithms() {
		Methods[algorithm] = jwt.GetSigningMethod(algorithm)
	}
	delete(Methods, "none")
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

func ValidateAlgorithm(algorithm string) error {
	_, ok := Methods[algorithm]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAlgorithm, algorithm)
	}
	return nil
}
