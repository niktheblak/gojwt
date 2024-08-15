package signing

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrUnexpectedAlgorithm = errors.New("unexpected signing algorithm")
)

func ValidateMethod(algorithm string, token *jwt.Token) error {
	if algorithm != token.Method.Alg() {
		return fmt.Errorf("%w: %v", ErrUnexpectedAlgorithm, token.Header["alg"])
	}
	return nil
}
