package errors

import (
	"errors"
)

// Errors related to JSON web tokens
var (
	ErrExpiredToken     = errors.New("Token has expired")
	ErrInvalidHeader    = errors.New("Token has invalid header")
	ErrInvalidType      = errors.New("Invalid token type")
	ErrInvalidAlgorithm = errors.New("Invalid or unsupported algorithm")
	ErrInvalidSignature = errors.New("Invalid signature")
	ErrMalformedToken   = errors.New("Malformed token content")
)
