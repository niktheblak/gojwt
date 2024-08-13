package jwt

import (
	"errors"
)

// Errors related to JSON web tokens
var (
	ErrInvalidToken     = errors.New("token is not valid")
	ErrInvalidHeader    = errors.New("token has invalid header")
	ErrInvalidType      = errors.New("invalid token type")
	ErrInvalidAlgorithm = errors.New("invalid or unsupported signing algorithm")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrMalformedToken   = errors.New("malformed token content")
	ErrContextNotSet    = errors.New("token context has not been set")
)
