package sign

import "errors"

var ErrInvalidSignature = errors.New("Invalid signature")

type Signer interface {
	Algorithm() string
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
