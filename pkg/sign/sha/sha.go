package sha

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/niktheblak/gojwt/pkg/sign"
)

type shaSigner struct {
	algo   sign.Algorithm
	hash   func() hash.Hash
	secret []byte
}

func HS256(secret []byte) sign.Signer {
	return shaSigner{
		algo:   sign.HS256,
		hash:   sha256.New,
		secret: secret,
	}
}

func ES256(secret []byte) sign.Signer {
	return shaSigner{
		algo:   sign.ES256,
		hash:   sha512.New512_256,
		secret: secret,
	}
}

func (s shaSigner) newMac() hash.Hash {
	return hmac.New(s.hash, s.secret)
}

func (s shaSigner) Algorithm() sign.Algorithm {
	return s.algo
}

func (s shaSigner) Sign(data string) ([]byte, error) {
	mac := s.newMac()
	mac.Write([]byte(data))
	return mac.Sum(nil), nil
}

func (s shaSigner) Verify(data string, signature []byte) error {
	mac := s.newMac()
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return sign.ErrInvalidSignature
	}
	return nil
}
