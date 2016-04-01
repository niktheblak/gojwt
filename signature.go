package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type Signer struct {
	Secret []byte
}

func (s Signer) Sign(data []byte) []byte {
	return Sign(s.Secret, data)
}

func (s Signer) Verify(data, checksum []byte) error {
	return Verify(s.Secret, data, checksum)
}

func Sign(secret, data []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	signature := mac.Sum(nil)
	return signature
}

func Verify(secret, data, signature []byte) error {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
