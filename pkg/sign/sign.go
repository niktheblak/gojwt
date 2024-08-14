package sign

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	ES256 Algorithm = "ES256"
	RS256 Algorithm = "RS256"
)

func ParseAlgorithm(alg string) (Algorithm, error) {
	switch alg {
	case "HS256":
		return HS256, nil
	case "ES256":
		return ES256, nil
	case "RS256":
		return RS256, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, alg)
	}
}

type Signer interface {
	Algorithm() Algorithm
	Sign(data string) ([]byte, error)
	Verify(data string, signature []byte) error
}
