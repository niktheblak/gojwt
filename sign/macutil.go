package sign

import (
	"crypto/hmac"
	"hash"

	"github.com/niktheblak/jwt/errors"
)

func VerifyMAC(mac hash.Hash, signature []byte) error {
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return errors.ErrInvalidSignature
	}
	return nil
}
