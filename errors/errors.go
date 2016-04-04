package errors

import (
	"errors"
)

var (
	ErrExpiredToken     = errors.New("Token has expired")
	ErrInvalidHeader    = errors.New("Token has invalid header")
	ErrInvalidType      = errors.New("Invalid token type")
	ErrInvalidAlgorithm = errors.New("Invalid signature algorithm")
	ErrMalformedToken   = errors.New("Malformed token content")
)
