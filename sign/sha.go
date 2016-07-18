package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type shaSigner struct {
	algo   string
	hash   func() hash.Hash
	secret []byte
}

func HS256(secret []byte) Signer {
	return shaSigner{
		algo:   "HS256",
		hash:   sha256.New,
		secret: secret,
	}
}

func ES256(secret []byte) Signer {
	return shaSigner{
		algo:   "ES256",
		hash:   sha512.New512_256,
		secret: secret,
	}
}

func (s shaSigner) newMac() hash.Hash {
	return hmac.New(s.hash, s.secret)
}

func (s shaSigner) Algorithm() string {
	return s.algo
}

func (s shaSigner) Sign(data string) []byte {
	mac := s.newMac()
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func (s shaSigner) Verify(data string, signature []byte) error {
	mac := s.newMac()
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
