package jwt

import (
	"errors"
)

var (
	ErrInvalidSignature = errors.New("Token signature does not match")
	ErrExpiredToken     = errors.New("Token has expired")
	ErrInvalidHeader    = errors.New("Token has invalid header")
	ErrInvalidType      = errors.New("Invalid token type")
	ErrInvalidAlgorithm = errors.New("Invalid signature algorithm")
	ErrMalformedToken   = errors.New("Malformed token content")
)
