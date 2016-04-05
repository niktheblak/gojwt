package sign

import "errors"

// Signature-related errors
var (
	ErrInvalidSignature = errors.New("Invalid signature")
)

type Signer interface {
	Algorithm() Algorithm
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
