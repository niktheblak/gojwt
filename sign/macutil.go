package sign

import (
	"crypto/hmac"
	"hash"
)

func VerifyMAC(mac hash.Hash, signature []byte) error {
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
