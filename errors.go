package jwt

import (
	"errors"
)

// Errors related to JSON web tokens
var (
	ErrExpiredToken     = errors.New("Token is not valid at this time")
	ErrInvalidHeader    = errors.New("Token has invalid header")
	ErrInvalidType      = errors.New("Invalid token type")
	ErrInvalidAlgorithm = errors.New("Invalid or unsupported signing algorithm")
	ErrMalformedToken   = errors.New("Malformed token content")
	ErrMissingSigner    = errors.New("Token signer has not been set")
	ErrMissingHeader    = errors.New("Token header has not been set")
	ErrMissingType      = errors.New("Token type has not been set")
	ErrMissingAlgorithm = errors.New("Token signing algorithm has not been set")
	ErrContextNotSet    = errors.New("Token context has not been set")
)
