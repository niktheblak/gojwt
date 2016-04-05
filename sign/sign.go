package sign

import "github.com/niktheblak/jwt/sign/algorithm"

type Signer interface {
	Algorithm() algorithm.Algorithm
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
