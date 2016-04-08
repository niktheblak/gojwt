package errors

import (
	"errors"
)

// Errors related to JSON web tokens
var (
	ErrExpiredToken     = errors.New("Token has expired")
	ErrInvalidHeader    = errors.New("Token has invalid header")
	ErrInvalidType      = errors.New("Invalid token type")
	ErrInvalidAlgorithm = errors.New("Invalid or unsupported signing algorithm")
	ErrInvalidSignature = errors.New("Invalid signature")
	ErrMalformedToken   = errors.New("Malformed token content")
	ErrMissingSigner    = errors.New("Token signer has not been set")
	ErrMissingHeader    = errors.New("Token header has not been set")
	ErrMissingType      = errors.New("Token type has not been set")
	ErrMissingAlgorithm = errors.New("Token signing algorithm has not been set")
)
