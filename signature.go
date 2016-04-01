package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type Signer struct {
	Secret []byte
}

func (s Signer) Sign(data string) []byte {
	return Sign(s.Secret, data)
}

func (s Signer) Verify(data string, signature []byte) error {
	return Verify(s.Secret, data, signature)
}

func Sign(secret []byte, data string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	signature := mac.Sum(nil)
	return signature
}

func Verify(secret []byte, data string, signature []byte) error {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
