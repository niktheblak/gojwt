package sign

import (
	"errors"

	"github.com/niktheblak/jwt/sign/algorithm"
)

// Signature-related errors
var (
	ErrInvalidSignature = errors.New("Invalid signature")
)

type Signer interface {
	Algorithm() algorithm.Algorithm
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
