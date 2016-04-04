package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

var (
	ErrInvalidSignature = errors.New("Invalid signature")
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
	mac := NewMac(secret)
	mac.Write([]byte(data))
	signature := mac.Sum(nil)
	return signature
}

func Verify(secret []byte, data string, signature []byte) error {
	mac := NewMac(secret)
	mac.Write([]byte(data))
	return VerifyMAC(mac, signature)
}

func NewMac(secret []byte) hash.Hash {
	return hmac.New(sha256.New, secret)
}

func VerifyMAC(mac hash.Hash, signature []byte) error {
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
